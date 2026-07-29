import {
  existsSync,
} from "node:fs";
import { resolve } from "node:path";
import {
  CandidateLinuxTransportBindingRegistry,
  candidateLinuxTargetScopesEqual,
  loadTrustedCandidateLinuxTransportBindingManifest,
} from "../../server/autonomous-runtime";
import { createDatabaseConnection } from "../../server/db";
import {
  V2_SESSION_COOKIE,
} from "../../server/auth/LocalSessionAuth";
import {
  runBoundedReleaseCommand,
  type BoundedReleaseCommandResult,
} from "./BoundedReleaseCommand";
import {
  withRootOperatorToken,
} from "./AuthenticatedNmapActivationVerifier";
import type {
  ActiveV2Work,
} from "./FunctionalReleasePrimitives";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH,
  REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
  type PreparedReviewedRealCandidateLinuxActivation,
  type ReviewedRealCandidateLinuxActivationInstaller,
  type ReviewedRealCandidateLinuxActivationPaths,
  type ReviewedRealCandidateLinuxActivationReceipt,
} from "./ReviewedRealCandidateLinuxActivationBundle";

export const REVIEWED_REAL_CANDIDATE_LINUX_FORWARD_ACTIVATION_SCHEMA_VERSION =
  "ti-scale.reviewed-real-candidate-linux-forward-activation.v1" as const;
export const REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_CONFIRMATION =
  "ACTIVATE_TI_SCALE_REVIEWED_REAL_CANDIDATE_LINUX_ON_3132" as const;

export const REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT =
  "ti-scale-reviewed-candidate-linux-adapter.service" as const;
export const REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT =
  "ti-scale-reviewed-candidate-linux-broker.service" as const;
export const TI_SCALE_APPLICATION_UNIT = "ti-scale.service" as const;
export const TI_SCALE_APPLICATION_FRAGMENT =
  "/etc/systemd/system/ti-scale.service" as const;
export const TI_SCALE_APPLICATION_ORIGIN = "http://127.0.0.1:3132" as const;

const SYSTEMCTL = "/usr/bin/systemctl";
const RUNUSER = "/usr/sbin/runuser";
const ENV = "/usr/bin/env";
const EXACT_PATH =
  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SERVICE_PROPERTIES = Object.freeze([
  "--property=Id",
  "--property=LoadState",
  "--property=ActiveState",
  "--property=SubState",
  "--property=Result",
  "--property=MainPID",
  "--property=FragmentPath",
  "--property=DropInPaths",
  "--property=UnitFileState",
  "--property=NeedDaemonReload",
] as const);
const SERVICE_PROPERTY_NAMES = Object.freeze([
  "ActiveState",
  "DropInPaths",
  "FragmentPath",
  "Id",
  "LoadState",
  "MainPID",
  "NeedDaemonReload",
  "Result",
  "SubState",
  "UnitFileState",
] as const);
const MAX_HTTP_BYTES = 2 * 1_024 * 1_024;

export interface ReviewedCandidateActivationCommandPort {
  run(
    command: readonly string[],
    options: Readonly<{
      timeoutMs: number;
      signal?: AbortSignal;
    }>,
  ): Promise<Readonly<{
    stdout: string;
    stderr: string;
  }>>;
}

export interface ReviewedCandidateActivationInstallerPort {
  prepare(): PreparedReviewedRealCandidateLinuxActivation;
  install(): ReviewedRealCandidateLinuxActivationReceipt;
  verifyInstalled(): ReviewedRealCandidateLinuxActivationReceipt;
}

export interface ReviewedCandidateServiceIdentity {
  readonly unit: string;
  readonly activeState: "active";
  readonly subState: "running";
  readonly result: "success";
  readonly mainPid: number;
  readonly fragmentPath: string;
  readonly unitFileState: string;
}

export interface ReviewedCandidateTransportActivationProof {
  readonly status: "ready";
  readonly code: "candidate_linux_transport_ready";
  readonly readinessScope: "reviewed_real_candidate";
  readonly activationModel: "run_scoped_after_discovery";
  readonly conditionalPlanningReady: true;
  readonly missionExecutionReady: boolean;
  readonly manifestSha256: string;
  readonly bindingIds: readonly string[];
  readonly targetScopes: readonly
    PreparedReviewedRealCandidateLinuxActivation["manifest"]["bindings"][number]["targetScope"][];
  readonly expiresAt: string;
}

export interface ReviewedCandidateApplicationActivationProof {
  readonly origin: typeof TI_SCALE_APPLICATION_ORIGIN;
  readonly liveness: "healthy";
  readonly readiness: "healthy";
  readonly databaseHealthy: true;
  readonly eventStreamHealthy: true;
  readonly authenticationConfigured: true;
  readonly authenticatedRoundTrip: true;
  readonly actorId: string;
  readonly sessionExpiresAt: string;
}

export interface ReviewedCandidateActivationVerifierPort {
  verifyCandidate(
    prepared: PreparedReviewedRealCandidateLinuxActivation,
    signal?: AbortSignal,
  ): Promise<ReviewedCandidateTransportActivationProof>;
  verifyApplication(
    signal?: AbortSignal,
  ): Promise<ReviewedCandidateApplicationActivationProof>;
}

export interface ReviewedCandidateForwardActivationReceipt {
  readonly schemaVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_FORWARD_ACTIVATION_SCHEMA_VERSION;
  readonly status: "activated";
  readonly bundleVersion: string;
  readonly applicationOrigin: typeof TI_SCALE_APPLICATION_ORIGIN;
  readonly backupCreated: false;
  readonly rollbackPayloadCreated: false;
  readonly port3131Touched: false;
  readonly installed: ReviewedRealCandidateLinuxActivationReceipt;
  readonly registration: Readonly<{
    status: "registered";
    manifestSha256: string;
    records: readonly Readonly<{
      id: string;
      specHash: string;
      transportBindingId: string;
    }>[];
  }>;
  readonly services: Readonly<{
    adapter: ReviewedCandidateServiceIdentity;
    broker: ReviewedCandidateServiceIdentity;
    application: ReviewedCandidateServiceIdentity;
  }>;
  readonly candidateTransport: ReviewedCandidateTransportActivationProof;
  readonly application: ReviewedCandidateApplicationActivationProof;
  readonly activatedAt: string;
}

export interface ReviewedCandidateForwardActivationInspection {
  readonly schemaVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_FORWARD_ACTIVATION_SCHEMA_VERSION;
  readonly status: "source_verified_installation_absent"
    | "installed_exact_activation_not_verified";
  readonly bundleVersion: string;
  readonly backupCreated: false;
  readonly rollbackPayloadCreated: false;
  readonly port3131Touched: false;
  readonly sourceAuthority:
    ReviewedRealCandidateLinuxActivationReceipt["sourceAuthority"];
  readonly targetScope:
    ReviewedRealCandidateLinuxActivationReceipt["targetScope"];
  readonly installed: boolean;
  readonly nextRequiredAction: string;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (
    actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])
  ) {
    throw new Error(`${label} contains an unreviewed field`);
  }
}

function sameReceipt(
  actual: ReviewedRealCandidateLinuxActivationReceipt,
  expected: ReviewedRealCandidateLinuxActivationReceipt,
  label: string,
): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} differs from the exact prepared activation bundle`);
  }
}

function assertNoActiveWork(snapshot: ActiveV2Work): void {
  if (
    snapshot.activeRuns.length > 0
    || snapshot.activeLeases.length > 0
    || snapshot.activeDatabaseWriters.length > 0
  ) {
    throw new Error(
      "Ti-Scale has active work; reviewed candidate activation is refused until runs, leases, and database writers are durably inactive",
    );
  }
}

function registrationCommand(
  prepared: PreparedReviewedRealCandidateLinuxActivation,
  databasePath: string,
  paths: ReviewedRealCandidateLinuxActivationPaths,
): readonly string[] {
  return Object.freeze([
    RUNUSER,
    "--user",
    "ti-scale",
    "--",
    ENV,
    "-i",
    `PATH=${EXACT_PATH}`,
    "HOME=/var/lib/ti-scale",
    `TI_SCALE_CANDIDATE_LINUX_TRUST_ROOT=${paths.trustRoot}`,
    `TI_SCALE_CANDIDATE_LINUX_MANIFEST_PATH=${paths.manifest}`,
    `TI_SCALE_CANDIDATE_LINUX_MANIFEST_SHA256=${prepared.manifestSha256}`,
    `TI_SCALE_DATABASE_PATH=${databasePath}`,
    paths.registerExecutable,
  ]);
}

function parseRegistration(
  stdout: string,
  prepared: PreparedReviewedRealCandidateLinuxActivation,
): ReviewedCandidateForwardActivationReceipt["registration"] {
  let decoded: unknown;
  try {
    decoded = JSON.parse(stdout.trim()) as unknown;
  } catch {
    throw new Error("Reviewed candidate registration did not return JSON");
  }
  const root = object(decoded, "Reviewed candidate registration");
  exactKeys(
    root,
    ["manifestSha256", "records", "status"],
    "Reviewed candidate registration",
  );
  if (
    root.status !== "registered"
    || root.manifestSha256 !== prepared.manifestSha256
    || !Array.isArray(root.records)
    || root.records.length !== prepared.manifest.bindings.length
  ) {
    throw new Error(
      "Reviewed candidate registration did not prove the exact manifest",
    );
  }
  const records = root.records.map((value, index) => {
    const record = object(value, "Reviewed candidate registration record");
    exactKeys(
      record,
      ["id", "specHash", "transportBindingId"],
      "Reviewed candidate registration record",
    );
    const binding = prepared.manifest.bindings[index];
    if (
      !binding
      || record.id !== binding.postExploitSpecId
      || record.specHash !== binding.postExploitSpecSha256
      || record.transportBindingId !== binding.bindingId
    ) {
      throw new Error(
        "Reviewed candidate registration record differs from the installed binding",
      );
    }
    return Object.freeze({
      id: String(record.id),
      specHash: String(record.specHash),
      transportBindingId: String(record.transportBindingId),
    });
  });
  return Object.freeze({
    status: "registered" as const,
    manifestSha256: prepared.manifestSha256,
    records: Object.freeze(records),
  });
}

function parseProperties(stdout: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of stdout.trim().split("\n")) {
    const separator = line.indexOf("=");
    if (separator < 1) {
      throw new Error("systemctl show returned malformed unit properties");
    }
    const key = line.slice(0, separator);
    if (Object.hasOwn(result, key)) {
      throw new Error("systemctl show returned a duplicate unit property");
    }
    result[key] = line.slice(separator + 1);
  }
  exactKeys(result, SERVICE_PROPERTY_NAMES, "systemctl show result");
  return result;
}

function assertNoUnrelatedBoundary(command: readonly string[]): void {
  const flattened = command.join("\u0000").toLocaleLowerCase("en-US");
  if (
    flattened.includes("3131")
    || flattened.includes("chillspwn")
    || flattened.includes("backup")
    || flattened.includes("snapshot")
    || flattened.includes("rollback")
  ) {
    throw new Error(
      "Reviewed candidate activation command escaped the Ti-Scale 3132 forward-only boundary",
    );
  }
}

export function assertReviewedCandidateActivationCommand(
  command: readonly string[],
): void {
  assertNoUnrelatedBoundary(command);
  if (command[0] === SYSTEMCTL) {
    const operation = command[1];
    const exact = JSON.stringify(command);
    const permitted = new Set([
      JSON.stringify([SYSTEMCTL, "daemon-reload"]),
      JSON.stringify([
        SYSTEMCTL,
        "enable",
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
        REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
      ]),
      JSON.stringify([
        SYSTEMCTL,
        "start",
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
      ]),
      JSON.stringify([
        SYSTEMCTL,
        "start",
        REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
      ]),
      JSON.stringify([SYSTEMCTL, "restart", TI_SCALE_APPLICATION_UNIT]),
      ...[
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
        REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
        TI_SCALE_APPLICATION_UNIT,
      ].map((unit) =>
        JSON.stringify([
          SYSTEMCTL,
          "show",
          unit,
          "--no-pager",
          ...SERVICE_PROPERTIES,
        ])),
    ]);
    if (!permitted.has(exact) || !operation) {
      throw new Error("Unreviewed systemctl operation in candidate activation");
    }
    return;
  }
  if (
    command[0] !== RUNUSER
    || command[1] !== "--user"
    || command[2] !== "ti-scale"
    || command[3] !== "--"
    || command[4] !== ENV
    || command[5] !== "-i"
    || command.at(-1)
      !== REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS.registerExecutable
    || command.some((value) => /[\r\n\u0000]/u.test(value))
  ) {
    throw new Error("Unreviewed registration command in candidate activation");
  }
}

export class BoundedReviewedCandidateActivationCommandPort
implements ReviewedCandidateActivationCommandPort {
  async run(
    command: readonly string[],
    options: Readonly<{ timeoutMs: number; signal?: AbortSignal }>,
  ): Promise<BoundedReleaseCommandResult> {
    assertReviewedCandidateActivationCommand(command);
    return await runBoundedReleaseCommand(command, {
      timeoutMs: options.timeoutMs,
      outputLimitBytes: 256 * 1_024,
      ...(options.signal ? { signal: options.signal } : {}),
    });
  }
}

async function boundedJson(response: Response): Promise<unknown> {
  const advertised = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(advertised) && advertised > MAX_HTTP_BYTES) {
    throw new Error("Ti-Scale activation response exceeded its size boundary");
  }
  const buffer = Buffer.from(await response.arrayBuffer());
  try {
    if (buffer.byteLength > MAX_HTTP_BYTES) {
      throw new Error("Ti-Scale activation response exceeded its size boundary");
    }
    return JSON.parse(buffer.toString("utf8")) as unknown;
  } catch (error) {
    if (error instanceof Error && error.message.includes("size boundary")) {
      throw error;
    }
    throw new Error("Ti-Scale activation response was not valid JSON");
  } finally {
    buffer.fill(0);
  }
}

function sessionCookie(headers: Headers): string {
  const values = (
    headers as Headers & { getSetCookie?: () => string[] }
  ).getSetCookie?.() ?? [headers.get("set-cookie") ?? ""];
  for (const value of values) {
    const match = new RegExp(
      `(?:^|[, ])${V2_SESSION_COOKIE}=([^;,\\s]+)`,
      "u",
    ).exec(value);
    if (match?.[1]) return `${V2_SESSION_COOKIE}=${match[1]}`;
  }
  throw new Error("Ti-Scale authentication did not issue the session cookie");
}

type Fetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export class ReviewedCandidateLiveActivationVerifier
implements ReviewedCandidateActivationVerifierPort {
  readonly #fetch: Fetch;
  readonly #origin: typeof TI_SCALE_APPLICATION_ORIGIN;
  readonly #databasePath: string;
  readonly #paths: ReviewedRealCandidateLinuxActivationPaths;
  readonly #tokenPath: string;
  readonly #tokenTrustRoot: string;
  readonly #deadlineMs: number;
  readonly #requestTimeoutMs: number;
  readonly #pollIntervalMs: number;

  constructor(options: Readonly<{
    fetch?: Fetch;
    databasePath?: string;
    paths?: ReviewedRealCandidateLinuxActivationPaths;
    tokenPath?: string;
    tokenTrustRoot?: string;
    deadlineMs?: number;
    requestTimeoutMs?: number;
    pollIntervalMs?: number;
  }> = {}) {
    this.#fetch = options.fetch ?? fetch;
    this.#origin = TI_SCALE_APPLICATION_ORIGIN;
    this.#databasePath = resolve(
      options.databasePath
        ?? REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH,
    );
    this.#paths =
      options.paths ?? REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS;
    this.#tokenPath = options.tokenPath ?? "/etc/ti-scale/operator-token";
    this.#tokenTrustRoot = options.tokenTrustRoot ?? "/etc/ti-scale";
    this.#deadlineMs = options.deadlineMs ?? 90_000;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 3_000;
    this.#pollIntervalMs = options.pollIntervalMs ?? 500;
    for (const [name, value] of Object.entries({
      deadlineMs: this.#deadlineMs,
      requestTimeoutMs: this.#requestTimeoutMs,
      pollIntervalMs: this.#pollIntervalMs,
    })) {
      if (!Number.isSafeInteger(value) || value < 1 || value > 180_000) {
        throw new Error(`${name} is outside the activation verification bound`);
      }
    }
  }

  async #request(
    path: string,
    init: RequestInit = {},
  ): Promise<Readonly<{ body: unknown; headers: Headers }>> {
    const response = await this.#fetch(`${this.#origin}${path}`, {
      ...init,
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(this.#requestTimeoutMs),
      headers: {
        Accept: "application/json",
        ...init.headers,
      },
    });
    if (response.status !== 200) {
      throw new Error(
        `Ti-Scale activation endpoint ${path} returned HTTP ${String(response.status)}`,
      );
    }
    return Object.freeze({
      body: await boundedJson(response),
      headers: response.headers,
    });
  }

  async #wait<T>(
    operation: () => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    const deadline = performance.now() + this.#deadlineMs;
    let last = "no live observation";
    do {
      if (signal?.aborted) {
        throw signal.reason instanceof Error
          ? signal.reason
          : new Error("Candidate activation verification was cancelled");
      }
      try {
        return await operation();
      } catch (error) {
        last = error instanceof Error ? error.message : "unknown live error";
      }
      await Bun.sleep(this.#pollIntervalMs);
    } while (performance.now() < deadline);
    throw new Error(
      `Ti-Scale did not reach exact activation readiness: ${last}`,
    );
  }

  async verifyCandidate(
    prepared: PreparedReviewedRealCandidateLinuxActivation,
    signal?: AbortSignal,
  ): Promise<ReviewedCandidateTransportActivationProof> {
    return await this.#wait(async () => {
      const manifest = loadTrustedCandidateLinuxTransportBindingManifest({
        path: this.#paths.manifest,
        trustRoot: this.#paths.trustRoot,
        expectedSha256: prepared.manifestSha256,
        allowedOwnerUids: [0],
        maximumBytes: 64 * 1_024,
      });
      const database = createDatabaseConnection({
        filename: this.#databasePath,
        readonly: true,
        fileMustExist: true,
        busyTimeoutMs: 5_000,
        verifyIntegrity: false,
      });
      try {
        const registry = new CandidateLinuxTransportBindingRegistry({
          database,
          loadedManifest: manifest,
        });
        await registry.attest(signal ?? new AbortController().signal);
        const readiness = registry.readiness();
        const expectedBindingIds = prepared.manifest.bindings.map(
          ({ bindingId }) => bindingId,
        );
        const expectedTargetScopes = prepared.manifest.bindings.map(
          ({ targetScope }) => targetScope,
        );
        if (
          readiness.status !== "ready"
          || readiness.code !== "candidate_linux_transport_ready"
          || readiness.readinessScope !== "reviewed_real_candidate"
          || readiness.activationModel !== "run_scoped_after_discovery"
          || readiness.conditionalPlanningReady !== true
          || readiness.candidateProcedurePresentAtLaunch !== true
          || readiness.procedureProviderPresentAtLaunch !== true
          || readiness.runScopedProcedureActivationPresentAtLaunch !== false
          || readiness.candidateDispatchAuthorityPresentAtLaunch !== false
          || readiness.manifestSha256 !== prepared.manifestSha256
          || readiness.bindingIds.length !== expectedBindingIds.length
          || readiness.bindingIds.some(
            (bindingId, index) => bindingId !== expectedBindingIds[index],
          )
          || readiness.targetScopes.length !== expectedTargetScopes.length
          || readiness.targetScopes.some((scope, index) =>
            !candidateLinuxTargetScopesEqual(
              scope,
              expectedTargetScopes[index]!,
            ))
          || !readiness.expiresAt
          || Date.parse(readiness.expiresAt) <= Date.now()
        ) {
          throw new Error(
            "The broker did not return the exact current reviewed candidate attestation",
          );
        }
        return Object.freeze({
          status: "ready" as const,
          code: "candidate_linux_transport_ready" as const,
          readinessScope: "reviewed_real_candidate" as const,
          activationModel: "run_scoped_after_discovery" as const,
          conditionalPlanningReady: true as const,
          missionExecutionReady: readiness.missionExecutionReady,
          manifestSha256: readiness.manifestSha256,
          bindingIds: Object.freeze([...readiness.bindingIds]),
          targetScopes: Object.freeze([...readiness.targetScopes]),
          expiresAt: readiness.expiresAt,
        });
      } finally {
        database.close();
      }
    }, signal);
  }

  async verifyApplication(
    signal?: AbortSignal,
  ): Promise<ReviewedCandidateApplicationActivationProof> {
    return await this.#wait(async () => {
      const [healthResult, readinessResult, sessionResult] =
        await Promise.all([
          this.#request("/api/v2/health"),
          this.#request("/api/v2/system/readiness"),
          this.#request("/api/v2/auth/session"),
        ]);
      const health = object(healthResult.body, "Ti-Scale health");
      const healthDatabase = object(
        health.database,
        "Ti-Scale health database",
      );
      const healthEvents = object(
        health.eventStream,
        "Ti-Scale health event stream",
      );
      const readiness = object(
        readinessResult.body,
        "Ti-Scale readiness",
      );
      const readinessDatabase = object(
        readiness.database,
        "Ti-Scale readiness database",
      );
      const readinessEvents = object(
        readiness.eventStream,
        "Ti-Scale readiness event stream",
      );
      const session = object(
        sessionResult.body,
        "Ti-Scale authentication readiness",
      );
      if (
        health.schemaVersion !== "2.4"
        || health.status !== "healthy"
        || healthDatabase.healthy !== true
        || healthEvents.status !== "healthy"
        || readiness.schemaVersion !== "2.4"
        || readiness.status !== "healthy"
        || readinessDatabase.healthy !== true
        || readinessEvents.status !== "healthy"
        || session.schemaVersion !== "2.4"
        || session.configured !== true
        || session.authenticated !== false
      ) {
        throw new Error(
          "Ti-Scale health, readiness, or authentication is not exact",
        );
      }
      return await withRootOperatorToken(
        this.#tokenPath,
        this.#tokenTrustRoot,
        async (token) => {
          const login = await this.#request("/api/v2/auth/session", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ operatorToken: token }),
          });
          const loginBody = object(login.body, "Ti-Scale authentication");
          const cookie = sessionCookie(login.headers);
          const authenticated = await this.#request(
            "/api/v2/auth/session",
            { headers: { Cookie: cookie } },
          );
          const authenticatedBody = object(
            authenticated.body,
            "Ti-Scale authenticated session",
          );
          const actorId = String(authenticatedBody.actorId ?? "");
          const expiresAt = String(authenticatedBody.expiresAt ?? "");
          if (
            loginBody.schemaVersion !== "2.4"
            || loginBody.authenticated !== true
            || authenticatedBody.schemaVersion !== "2.4"
            || authenticatedBody.configured !== true
            || authenticatedBody.authenticated !== true
            || !actorId
            || Date.parse(expiresAt) <= Date.now()
          ) {
            throw new Error(
              "Ti-Scale did not complete an authenticated session round trip",
            );
          }
          return Object.freeze({
            origin: this.#origin,
            liveness: "healthy" as const,
            readiness: "healthy" as const,
            databaseHealthy: true as const,
            eventStreamHealthy: true as const,
            authenticationConfigured: true as const,
            authenticatedRoundTrip: true as const,
            actorId,
            sessionExpiresAt: expiresAt,
          });
        },
      );
    }, signal);
  }
}

export class ReviewedRealCandidateLinuxForwardActivation {
  readonly #installer: ReviewedCandidateActivationInstallerPort;
  readonly #commands: ReviewedCandidateActivationCommandPort;
  readonly #verifier: ReviewedCandidateActivationVerifierPort;
  readonly #databasePath: string;
  readonly #paths: ReviewedRealCandidateLinuxActivationPaths;
  readonly #readActiveWork: () => ActiveV2Work;
  readonly #exists: (path: string) => boolean;
  readonly #clock: () => Date;

  constructor(input: Readonly<{
    installer: ReviewedCandidateActivationInstallerPort;
    commands: ReviewedCandidateActivationCommandPort;
    verifier: ReviewedCandidateActivationVerifierPort;
    databasePath?: string;
    paths?: ReviewedRealCandidateLinuxActivationPaths;
    readActiveWork: () => ActiveV2Work;
    exists?: (path: string) => boolean;
    clock?: () => Date;
  }>) {
    this.#installer = input.installer;
    this.#commands = input.commands;
    this.#verifier = input.verifier;
    this.#databasePath = resolve(
      input.databasePath
        ?? REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH,
    );
    this.#paths =
      input.paths ?? REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS;
    this.#readActiveWork = input.readActiveWork;
    this.#exists = input.exists ?? existsSync;
    this.#clock = input.clock ?? (() => new Date());
  }

  inspect(): ReviewedCandidateForwardActivationInspection {
    const prepared = this.#installer.prepare();
    const filePresence = prepared.files.map(({ path }) => this.#exists(path));
    const trustRootPresent = this.#exists(this.#paths.trustRoot);
    const installed = trustRootPresent
      && filePresence.every(Boolean);
    if (
      (trustRootPresent || filePresence.some(Boolean))
      && !installed
    ) {
      throw new Error(
        "Reviewed candidate installation is partial; activation is refused",
      );
    }
    if (installed) {
      sameReceipt(
        this.#installer.verifyInstalled(),
        prepared.receipt,
        "Installed reviewed candidate receipt",
      );
    }
    return Object.freeze({
      schemaVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_FORWARD_ACTIVATION_SCHEMA_VERSION,
      status: installed
        ? "installed_exact_activation_not_verified"
        : "source_verified_installation_absent",
      bundleVersion: prepared.receipt.bundleVersion,
      backupCreated: false,
      rollbackPayloadCreated: false,
      port3131Touched: false,
      sourceAuthority: prepared.receipt.sourceAuthority,
      targetScope: prepared.receipt.targetScope,
      installed,
      nextRequiredAction: installed
        ? "Run activate with the exact confirmation to register, start, restart, and prove live Ti-Scale readiness."
        : "Run activate with the exact confirmation to install, register, start, restart, and prove live Ti-Scale readiness.",
    });
  }

  async #service(
    unit: string,
    expectedFragment: string,
    expectedDropIn: string | undefined,
    signal?: AbortSignal,
  ): Promise<ReviewedCandidateServiceIdentity> {
    const result = await this.#commands.run([
      SYSTEMCTL,
      "show",
      unit,
      "--no-pager",
      ...SERVICE_PROPERTIES,
    ], {
      timeoutMs: 15_000,
      ...(signal ? { signal } : {}),
    });
    const value = parseProperties(result.stdout);
    const mainPid = Number(value.MainPID);
    const dropInPaths = (value.DropInPaths ?? "")
      .split(/\s+/u)
      .filter(Boolean)
      .map((path) => resolve(path));
    if (
      value.Id !== unit
      || value.LoadState !== "loaded"
      || value.ActiveState !== "active"
      || value.SubState !== "running"
      || value.Result !== "success"
      || !Number.isSafeInteger(mainPid)
      || mainPid < 1
      || value.NeedDaemonReload !== "no"
      || resolve(value.FragmentPath ?? "") !== resolve(expectedFragment)
      || (
        expectedDropIn !== undefined
        && !dropInPaths.includes(resolve(expectedDropIn))
      )
    ) {
      throw new Error(`${unit} did not reach its exact active unit identity`);
    }
    return Object.freeze({
      unit,
      activeState: "active" as const,
      subState: "running" as const,
      result: "success" as const,
      mainPid,
      fragmentPath: String(value.FragmentPath),
      unitFileState: String(value.UnitFileState),
    });
  }

  async #assertLoadedUnit(
    unit: string,
    expectedFragment: string,
    expectedDropIn: string | undefined,
    signal?: AbortSignal,
  ): Promise<void> {
    const result = await this.#commands.run([
      SYSTEMCTL,
      "show",
      unit,
      "--no-pager",
      ...SERVICE_PROPERTIES,
    ], {
      timeoutMs: 15_000,
      ...(signal ? { signal } : {}),
    });
    const value = parseProperties(result.stdout);
    const dropInPaths = (value.DropInPaths ?? "")
      .split(/\s+/u)
      .filter(Boolean)
      .map((path) => resolve(path));
    if (
      value.Id !== unit
      || value.LoadState !== "loaded"
      || resolve(value.FragmentPath ?? "") !== resolve(expectedFragment)
      || value.NeedDaemonReload !== "no"
      || (
        expectedDropIn !== undefined
        && !dropInPaths.includes(resolve(expectedDropIn))
      )
    ) {
      throw new Error(`${unit} is not loaded from the exact installed unit`);
    }
  }

  async activate(
    signal?: AbortSignal,
  ): Promise<ReviewedCandidateForwardActivationReceipt> {
    const checkCancelled = (): void => {
      if (!signal?.aborted) return;
      throw signal.reason instanceof Error
        ? signal.reason
        : new Error("Reviewed candidate activation was cancelled");
    };
    checkCancelled();
    assertNoActiveWork(this.#readActiveWork());
    const prepared = this.#installer.prepare();
    const installed = this.#installer.install();
    sameReceipt(installed, prepared.receipt, "Installed activation receipt");
    sameReceipt(
      this.#installer.verifyInstalled(),
      prepared.receipt,
      "Verified activation receipt",
    );

    checkCancelled();
    const registrationResult = await this.#commands.run(
      registrationCommand(prepared, this.#databasePath, this.#paths),
      {
        timeoutMs: 30_000,
        ...(signal ? { signal } : {}),
      },
    );
    const registration = parseRegistration(
      registrationResult.stdout,
      prepared,
    );
    sameReceipt(
      this.#installer.verifyInstalled(),
      prepared.receipt,
      "Post-registration activation receipt",
    );

    checkCancelled();
    assertNoActiveWork(this.#readActiveWork());
    await this.#commands.run([SYSTEMCTL, "daemon-reload"], {
      timeoutMs: 30_000,
      ...(signal ? { signal } : {}),
    });
    await this.#assertLoadedUnit(
      REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
      this.#paths.adapterService,
      undefined,
      signal,
    );
    await this.#assertLoadedUnit(
      REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
      this.#paths.brokerService,
      undefined,
      signal,
    );
    await this.#assertLoadedUnit(
      TI_SCALE_APPLICATION_UNIT,
      TI_SCALE_APPLICATION_FRAGMENT,
      this.#paths.applicationDropIn,
      signal,
    );
    await this.#commands.run([
      SYSTEMCTL,
      "enable",
      REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
      REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
    ], {
      timeoutMs: 30_000,
      ...(signal ? { signal } : {}),
    });

    checkCancelled();
    await this.#commands.run([
      SYSTEMCTL,
      "start",
      REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
    ], {
      timeoutMs: 30_000,
      ...(signal ? { signal } : {}),
    });
    await this.#service(
      REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
      this.#paths.adapterService,
      undefined,
      signal,
    );
    await this.#commands.run([
      SYSTEMCTL,
      "start",
      REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
    ], {
      timeoutMs: 30_000,
      ...(signal ? { signal } : {}),
    });
    await this.#service(
      REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
      this.#paths.brokerService,
      undefined,
      signal,
    );

    checkCancelled();
    await this.#commands.run([
      SYSTEMCTL,
      "restart",
      TI_SCALE_APPLICATION_UNIT,
    ], {
      timeoutMs: 120_000,
      ...(signal ? { signal } : {}),
    });
    const adapter = await this.#service(
      REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
      this.#paths.adapterService,
      undefined,
      signal,
    );
    const broker = await this.#service(
      REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
      this.#paths.brokerService,
      undefined,
      signal,
    );
    const application = await this.#service(
      TI_SCALE_APPLICATION_UNIT,
      TI_SCALE_APPLICATION_FRAGMENT,
      this.#paths.applicationDropIn,
      signal,
    );
    if (
      adapter.unitFileState !== "enabled"
      || broker.unitFileState !== "enabled"
    ) {
      throw new Error(
        "Reviewed candidate adapter and broker are active but not enabled",
      );
    }

    checkCancelled();
    const candidateTransport = await this.#verifier.verifyCandidate(
      prepared,
      signal,
    );
    const applicationProof = await this.#verifier.verifyApplication(signal);
    sameReceipt(
      this.#installer.verifyInstalled(),
      prepared.receipt,
      "Final activation receipt",
    );
    return Object.freeze({
      schemaVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_FORWARD_ACTIVATION_SCHEMA_VERSION,
      status: "activated",
      bundleVersion: prepared.receipt.bundleVersion,
      applicationOrigin: TI_SCALE_APPLICATION_ORIGIN,
      backupCreated: false,
      rollbackPayloadCreated: false,
      port3131Touched: false,
      installed,
      registration,
      services: Object.freeze({
        adapter,
        broker,
        application,
      }),
      candidateTransport,
      application: applicationProof,
      activatedAt: this.#clock().toISOString(),
    });
  }
}
