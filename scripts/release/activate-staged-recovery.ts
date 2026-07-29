#!/usr/bin/env bun
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createDatabaseConnection } from "../../server/db/connection";
import { StaticArtifactReleaseStore } from "../../server/static-release";
import { runBoundedReleaseCommand } from "./BoundedReleaseCommand";
import { writeDurableFileAtomically } from "./DurableAtomicFile";
import { verifyServerRelease } from "./FunctionalReleasePrimitives";
import { acquireSharedReleaseLock } from "./ReleaseExecutionBoundary";

const APPLICATION_PATH = "/opt/ti-scale";
const SERVER_RELEASE_ROOT = "/opt/ti-scale-server-releases";
const STATIC_RELEASE_ROOT = "/var/lib/ti-scale/static-releases";
const DATABASE_PATH = "/var/lib/ti-scale/data/ti-scale.sqlite";
const RECEIPT_ROOT = "/var/lib/ti-scale/release-receipts";
const SERVICE = "ti-scale.service";
const LEGACY_SERVICE = "chillspwn.service";
const HEALTH_URL = "http://127.0.0.1:3132/api/v2/health";
const READINESS_URL = "http://127.0.0.1:3132/api/v2/system/readiness";
const LEGACY_HEALTH_URL = "http://127.0.0.1:3131/api/health";
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

interface ServiceProperties {
  readonly state: string;
  readonly pid: number;
  readonly invocationId: string;
  readonly controlGroup: string;
}

interface ServiceIdentity {
  readonly state: string;
  readonly pid: number;
  readonly invocationId: string;
  readonly healthStatus: number;
  readonly semanticStatus?: string;
}

interface HealthResult {
  readonly status: number;
  readonly semanticStatus: string;
  readonly body: Record<string, unknown>;
}

interface TiScaleHealthEvidence {
  readonly liveness: HealthResult;
  readonly readiness: HealthResult;
}

export type StagedRecoveryLegacyVerification =
  | "verified_unchanged"
  | "not_verified_on_failure";

export class StagedRecoveryPostLegacyVerificationError extends Error {
  readonly legacyVerification = "verified_unchanged" as const;

  constructor(cause: unknown) {
    const failure = cause instanceof Error
      ? cause
      : new Error(typeof cause === "string" ? cause : "Staged recovery failed");
    super(failure.message, { cause: failure });
    this.name = "StagedRecoveryPostLegacyVerificationError";
  }
}

export function stagedRecoveryLegacyVerificationFromError(
  error: unknown,
): StagedRecoveryLegacyVerification {
  if (error instanceof StagedRecoveryPostLegacyVerificationError) {
    return error.legacyVerification;
  }
  if (error instanceof Error && "cause" in error) {
    return stagedRecoveryLegacyVerificationFromError(
      (error as Error & { readonly cause?: unknown }).cause,
    );
  }
  return "not_verified_on_failure";
}

async function commandBounded(args: readonly string[], timeoutMs = 2_000): Promise<string> {
  const result = await runBoundedReleaseCommand(args, {
    timeoutMs,
    outputLimitBytes: 1_048_576,
    terminationGraceMs: 250,
  });
  return result.stdout;
}

async function serviceProperties(service: string): Promise<ServiceProperties> {
  const output = await commandBounded([
    "/usr/bin/systemctl", "show", service,
    "--property=ActiveState,MainPID,InvocationID,ControlGroup", "--no-pager",
  ]);
  const values = Object.fromEntries(output.split("\n").filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return index >= 0 ? [line.slice(0, index), line.slice(index + 1)] : [line, ""];
  }));
  return {
    state: values.ActiveState ?? "unknown",
    pid: Number(values.MainPID ?? 0),
    invocationId: values.InvocationID ?? "",
    controlGroup: values.ControlGroup ?? "",
  };
}

async function fetchHealth(url: string, timeoutMs = 2_000): Promise<HealthResult> {
  const response = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(timeoutMs) });
  const body = await response.json() as Record<string, unknown>;
  return {
    status: response.status,
    semanticStatus: typeof body.status === "string" ? body.status : "unknown",
    body,
  };
}

async function captureService(service: string, url: string): Promise<ServiceIdentity> {
  const properties = await serviceProperties(service);
  const health = await fetchHealth(url);
  return {
    state: properties.state,
    pid: properties.pid,
    invocationId: properties.invocationId,
    healthStatus: health.status,
    semanticStatus: health.semanticStatus,
  };
}

function databaseSchema(): number {
  const database = createDatabaseConnection({
    filename: DATABASE_PATH,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    return Number((database.prepare("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations").get() as { version: number }).version);
  } finally { database.close(); }
}

function assertDatabaseIntegrity(): { quickCheck: string; foreignKeyViolations: number } {
  const database = createDatabaseConnection({
    filename: DATABASE_PATH,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const quick = database.prepare("PRAGMA quick_check").all() as Array<Record<string, string>>;
    const quickCheck = String(Object.values(quick[0] ?? {})[0] ?? "missing");
    const foreignKeyViolations = (database.prepare("PRAGMA foreign_key_check").all() as unknown[]).length;
    if (quick.length !== 1 || quickCheck !== "ok" || foreignKeyViolations !== 0) {
      throw new Error(`Canonical database integrity failed: quick_check=${quickCheck}, foreign_keys=${String(foreignKeyViolations)}`);
    }
    return { quickCheck, foreignKeyViolations };
  } finally { database.close(); }
}

function writeReceipt(path: string, value: Record<string, unknown>): void {
  writeDurableFileAtomically(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function writeHashAtomically(path: string, value: string): void {
  writeDurableFileAtomically(path, value, { mode: 0o600 });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isExactIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function isHealthyLegacyIdentity(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  return value.state === "active" && isPositiveSafeInteger(value.pid) &&
    isNonEmptyString(value.invocationId) && value.healthStatus === 200 &&
    value.semanticStatus === "ok";
}

function isUnchangedHealthyLegacyIdentity(before: unknown, after: unknown): boolean {
  return isHealthyLegacyIdentity(before) && isHealthyLegacyIdentity(after) &&
    after.state === before.state && after.pid === before.pid &&
    after.invocationId === before.invocationId;
}

function isHealthyTiScaleIdentity(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return value.state === "active" && isPositiveSafeInteger(value.pid) &&
    isNonEmptyString(value.invocationId) && value.healthStatus === 200 &&
    value.semanticStatus === "healthy";
}

function hasHealthyFinalizedDatabase(
  receipt: Record<string, unknown>,
): receipt is Record<string, unknown> & {
  readonly database: Record<string, unknown> & { readonly targetSchema: number };
} {
  if (!isRecord(receipt.database)) return false;
  const integrityAfter = receipt.database.integrityAfter;
  return isNonNegativeSafeInteger(receipt.database.targetSchema) &&
    isRecord(integrityAfter) && integrityAfter.quickCheck === "ok" &&
    integrityAfter.foreignKeyViolations === 0;
}

function hasHealthyFinalizedHealth(receipt: Record<string, unknown>): boolean {
  if (!hasHealthyFinalizedDatabase(receipt) || !isRecord(receipt.health)) return false;
  const healthDatabase = receipt.health.database;
  return receipt.health.status === "healthy" && isRecord(healthDatabase) &&
    healthDatabase.healthy === true &&
    healthDatabase.currentMigration === receipt.database.targetSchema;
}

export function isResumeOnlyFinalizedReceipt(
  receipt: Record<string, unknown>,
  releaseId: string,
): boolean {
  return receipt.schemaVersion === "ti-scale.staged-recovery-activation.v1" &&
    receipt.releaseId === releaseId && receipt.status === "deployed" &&
    receipt.resumedFromPendingReceipt === true && receipt.resumeOnlyFinalization === true &&
    isExactIsoTimestamp(receipt.deployedAt) && hasHealthyFinalizedHealth(receipt) &&
    isUnchangedHealthyLegacyIdentity(receipt.legacyBefore, receipt.legacyAfter) &&
    isHealthyTiScaleIdentity(receipt.tiScaleAfter);
}

export function stagedRecoveryResumeDisposition(
  receipt: Record<string, unknown>,
  releaseId: string,
): "pending_finalization" | "checksum_repair" {
  if (
    receipt.schemaVersion === "ti-scale.staged-recovery-activation.v1" &&
    receipt.releaseId === releaseId && receipt.status === "activated_service_pending"
  ) return "pending_finalization";
  if (isResumeOnlyFinalizedReceipt(receipt, releaseId)) return "checksum_repair";
  throw new Error(
    "Only an exact activated_service_pending receipt or a self-marked resume-only checksum repair can be resumed",
  );
}

export function persistResumeOnlyFinalization(options: {
  readonly receiptPath: string;
  readonly receipt: Record<string, unknown>;
  readonly releaseId: string;
  readonly finalizedFields: Readonly<Record<string, unknown>>;
  readonly beforeChecksumWrite?: () => void;
}): { readonly receiptSha256: string; readonly checksumRepaired: boolean } {
  const wasPending = options.receipt.status === "activated_service_pending";
  const alreadyFinalized = isResumeOnlyFinalizedReceipt(options.receipt, options.releaseId);
  if (!wasPending && !alreadyFinalized) {
    throw new Error("Staged recovery receipt is neither pending nor an exact resume-only finalized receipt");
  }
  const requiredCurrentFields = ["health", "database", "legacyAfter", "tiScaleAfter"] as const;
  if (requiredCurrentFields.some((field) => !Object.hasOwn(options.finalizedFields, field))) {
    throw new Error(
      "Resume-only finalization requires recomputed current health, database integrity, and service identities",
    );
  }
  const finalized = {
    ...options.receipt,
    ...options.finalizedFields,
    status: "deployed",
    resumedFromPendingReceipt: true,
    resumeOnlyFinalization: true,
  };
  if (!isResumeOnlyFinalizedReceipt(finalized, options.releaseId)) {
    throw new Error("Resume-only finalization fields failed exact semantic validation");
  }
  // A checksum repair is a new observation boundary. Rewrite the receipt with
  // the values just recomputed by the caller instead of blessing stale bytes.
  writeReceipt(options.receiptPath, finalized);
  const durableBytes = readFileSync(options.receiptPath);
  const durable = JSON.parse(durableBytes.toString("utf8")) as Record<string, unknown>;
  if (!isResumeOnlyFinalizedReceipt(durable, options.releaseId)) {
    throw new Error("Durable resume-only receipt failed post-commit validation");
  }
  const receiptSha256 = createHash("sha256").update(durableBytes).digest("hex");
  options.beforeChecksumWrite?.();
  writeHashAtomically(
    join(dirname(options.receiptPath), "activation-receipt.sha256"),
    `${receiptSha256}  activation-receipt.json\n`,
  );
  return { receiptSha256, checksumRepaired: alreadyFinalized };
}

async function waitForAlreadyRunningHealth(expectedSchema: number): Promise<TiScaleHealthEvidence> {
  const deadline = performance.now() + 5 * 60_000;
  let last = "no response";
  while (performance.now() < deadline) {
    try {
      const liveness = await fetchHealth(
        HEALTH_URL,
        Math.min(3_000, Math.max(1, deadline - performance.now())),
      );
      const readiness = await fetchHealth(
        READINESS_URL,
        Math.min(3_000, Math.max(1, deadline - performance.now())),
      );
      last = `liveness=${String(liveness.status)}/${liveness.semanticStatus} ` +
        `readiness=${String(readiness.status)}/${readiness.semanticStatus} ` +
        JSON.stringify(readiness.body).slice(0, 500);
      const database = readiness.body.database as Record<string, unknown> | undefined;
      if (
        liveness.status === 200 && liveness.semanticStatus === "healthy" &&
        readiness.status === 200 && readiness.semanticStatus === "healthy" &&
        database?.healthy === true && Number(database.currentMigration) === expectedSchema
      ) return { liveness, readiness };
    } catch (error) { last = error instanceof Error ? error.message : "health/readiness request failed"; }
    await Bun.sleep(Math.min(1_000, Math.max(1, deadline - performance.now())));
  }
  throw new Error(`Ti-Scale pending recovery is not already healthy: ${last}`);
}

function cgroupProcessIds(controlGroup: string): readonly number[] {
  const segments = controlGroup.split("/").filter(Boolean);
  if (!controlGroup.startsWith("/") || segments.includes("..") || segments.at(-1) !== SERVICE) return [];
  const path = resolve("/sys/fs/cgroup", `.${controlGroup}`, "cgroup.procs");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split(/\s+/u).filter(Boolean).map(Number)
    .filter((pid) => Number.isSafeInteger(pid) && pid > 0);
}

function listenerProcessIds(output: string): readonly number[] {
  return [...new Set([...output.matchAll(/\bpid=(\d+)\b/gu)].map((match) => Number(match[1]))
    .filter((pid) => Number.isSafeInteger(pid) && pid > 0))];
}

async function assertTiScaleProcessOwnership(properties: ServiceProperties): Promise<void> {
  const cgroupPids = cgroupProcessIds(properties.controlGroup);
  const listenerPids = listenerProcessIds(await commandBounded([
    "/usr/bin/ss", "--no-header", "--tcp", "--listening", "--numeric", "--processes", "sport = :3132",
  ]));
  const members = new Set(cgroupPids);
  if (
    properties.state !== "active" || properties.pid <= 0 || !properties.invocationId ||
    !members.has(properties.pid) || listenerPids.length === 0 ||
    listenerPids.some((pid) => !members.has(pid))
  ) {
    throw new Error(
      `Ti-Scale pending runtime ownership is invalid: state=${properties.state}, pid=${String(properties.pid)}, ` +
      `cgroup=${properties.controlGroup || "missing"}, cgroupPids=${cgroupPids.join(",") || "none"}, ` +
      `listenerPids=${listenerPids.join(",") || "none"}`,
    );
  }
}

function parseArguments(args: readonly string[]): { releaseId: string; resume: boolean } {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!name?.startsWith("--") || !value || value.startsWith("--") || values.has(name)) {
      throw new Error("Expected unique --release-id, exactly one mode option, and --confirm");
    }
    values.set(name, value);
  }
  const releaseId = values.get("--release-id") ?? "";
  const resume = values.get("--resume") === "yes";
  const execute = values.get("--execute") === "yes";
  if (!RELEASE_ID.test(releaseId) || execute === resume || values.get("--confirm") !== releaseId) {
    throw new Error("Recovery requires --release-id ID and exactly one of --execute yes or --resume yes, plus --confirm ID");
  }
  if (values.size !== 3) throw new Error("Unsupported staged-recovery option");
  return { releaseId, resume };
}

export const STAGED_RECOVERY_EXECUTE_DISABLED_MESSAGE =
  "New staged-recovery activation is disabled; only the bounded forward-only no-backup controller may deploy Ti-Scale";

export function assertStagedRecoveryResumeOnly(resume: boolean): asserts resume {
  if (!resume) throw new Error(STAGED_RECOVERY_EXECUTE_DISABLED_MESSAGE);
}

export async function activateVerifiedStagedRecovery(args = process.argv.slice(2)): Promise<void> {
  const { releaseId, resume } = parseArguments(args);
  assertStagedRecoveryResumeOnly(resume);
  if (process.getuid?.() !== 0) throw new Error("Staged recovery requires root");

  const lock = acquireSharedReleaseLock(undefined, `staged-resume:${releaseId}`);
  const receiptDirectory = join(RECEIPT_ROOT, releaseId);
  const receiptPath = join(receiptDirectory, "activation-receipt.json");
  let legacyVerifiedUnchanged = false;
  try {
    if (!existsSync(receiptPath)) throw new Error("Staged recovery cannot resume without its activation receipt");
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as Record<string, unknown>;
    const resumeDisposition = stagedRecoveryResumeDisposition(receipt, releaseId);

    const recordedServer = receipt.serverRelease as Record<string, unknown>;
    const recordedStatic = receipt.staticRelease as Record<string, unknown>;
    const recordedActive = receipt.active as Record<string, unknown> | undefined;
    const recordedDatabase = receipt.database as Record<string, unknown>;
    const serverDirectory = join(SERVER_RELEASE_ROOT, "releases", releaseId);
    const server = await verifyServerRelease(serverDirectory, releaseId, String(recordedServer.manifestSha256));
    const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
    const verifiedStatic = staticStore.verifyRelease(releaseId, String(recordedStatic.manifestSha256));
    const activeStatic = staticStore.readActivePointer();
    const recordedActiveStatic = recordedActive?.staticPointer as Record<string, unknown> | undefined;
    if (
      realpathSync(String(recordedServer.path)) !== server.releaseDirectory ||
      realpathSync(String(recordedStatic.path)) !== verifiedStatic.releaseDirectory ||
      !lstatSync(APPLICATION_PATH).isSymbolicLink() || realpathSync(APPLICATION_PATH) !== server.releaseDirectory ||
      activeStatic.activeReleaseId !== releaseId || activeStatic.activeManifestSha256 !== verifiedStatic.manifestSha256 ||
      recordedActive?.applicationTarget !== server.releaseDirectory ||
      recordedActiveStatic?.activeReleaseId !== activeStatic.activeReleaseId ||
      recordedActiveStatic.activeManifestSha256 !== activeStatic.activeManifestSha256
    ) throw new Error("Active server/static state no longer matches the pending recovery receipt");

    const expectedSchema = Number(recordedDatabase.targetSchema);
    if (!Number.isSafeInteger(expectedSchema) || databaseSchema() !== expectedSchema) {
      throw new Error("Canonical schema changed before staged recovery finalization");
    }
    const health = await waitForAlreadyRunningHealth(expectedSchema);
    const integrityAfter = assertDatabaseIntegrity();

    const legacyBefore = receipt.legacyBefore as ServiceIdentity;
    const legacyAfter = await captureService(LEGACY_SERVICE, LEGACY_HEALTH_URL);
    if (
      legacyAfter.state !== legacyBefore.state || legacyAfter.pid !== legacyBefore.pid ||
      legacyAfter.invocationId !== legacyBefore.invocationId || legacyAfter.healthStatus !== 200 ||
      legacyAfter.semanticStatus !== "ok"
    ) throw new Error("Legacy ChillsPwn identity changed before staged recovery finalization");
    legacyVerifiedUnchanged = true;

    const tiScaleProperties = await serviceProperties(SERVICE);
    await assertTiScaleProcessOwnership(tiScaleProperties);
    const finalization = persistResumeOnlyFinalization({
      receiptPath,
      receipt,
      releaseId,
      finalizedFields: {
        deployedAt: resumeDisposition === "checksum_repair"
          ? receipt.deployedAt
          : new Date().toISOString(),
        // Preserve the rich readiness body as the durable dependency and
        // database evidence. Liveness remains the process identity proof.
        health: health.readiness.body,
        database: { ...recordedDatabase, integrityAfter },
        legacyAfter,
        tiScaleAfter: {
          state: tiScaleProperties.state,
          pid: tiScaleProperties.pid,
          invocationId: tiScaleProperties.invocationId,
          healthStatus: health.liveness.status,
          semanticStatus: health.liveness.semanticStatus,
        },
        staticRelease: { ...recordedStatic, path: verifiedStatic.releaseDirectory },
      },
    });
    process.stdout.write(`${JSON.stringify({
      status: "deployed",
      releaseId,
      receipt: receiptPath,
      receiptSha256: finalization.receiptSha256,
      legacy3131Unchanged: true,
      resumed: true,
      resumeOnlyFinalization: true,
      checksumRepaired: finalization.checksumRepaired,
      resumeDisposition,
    }, null, 2)}\n`);
  } catch (error) {
    if (legacyVerifiedUnchanged) {
      throw new StagedRecoveryPostLegacyVerificationError(error);
    }
    throw error;
  } finally {
    lock.release();
  }
}

if (import.meta.main) {
  activateVerifiedStagedRecovery().catch((error) => {
    const legacyVerification = stagedRecoveryLegacyVerificationFromError(error);
    process.stderr.write(`${JSON.stringify({
      status: "failed",
      message: error instanceof Error ? error.message : "Staged recovery failed",
      legacyMutationAttempted: false,
      legacyVerification,
      legacyServiceMutated: legacyVerification === "verified_unchanged" ? false : null,
    })}\n`);
    process.exitCode = 1;
  });
}
