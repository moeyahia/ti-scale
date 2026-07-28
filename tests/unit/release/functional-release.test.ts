import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertApplicationTreeFingerprint,
  canonicalApplicationTreeFingerprint,
  canonicalDatabaseFingerprint,
  canonicalReleaseDataFingerprint,
  exchangeApplicationTarget,
  queryActiveV2Work,
  stageServerRelease,
  verifyChecksumManifest,
  verifyServerRelease,
  writeAndVerifyChecksumManifest,
  RELEASE_DATA_FINGERPRINT_POLICY,
  RELEASE_DATA_FINGERPRINT_ROW_CLASS_EXCLUSIONS,
  RELEASE_DATA_FINGERPRINT_ROW_EXCLUDED_TABLES,
  type ChecksumManifestPublicationPhase,
} from "../../../scripts/release/FunctionalReleasePrimitives";
import {
  createDirectoryDurably,
  renameDirectoryDurably,
  writeDurableFileAtomically,
  type DurableDirectoryCreatePhase,
  type DurableDirectoryRenamePhase,
  type DurableAtomicWritePhase,
} from "../../../scripts/release/DurableAtomicFile";
import { createDatabaseConnection } from "../../../server/db/connection";
import { DATABASE_MIGRATIONS } from "../../../server/db/migrations";
import { migrateDatabase } from "../../../server/db/migrations/runner";
import { OperationalHazardObservationWorker } from "../../../server/memory/OperationalHazardObservationService";
import { EventRepository } from "../../../server/events/EventRepository";
import { EventStreamService } from "../../../server/events/EventStreamService";
import {
  CanonicalDatabaseLeaseConflictError,
  CanonicalDatabaseLeaseService,
  withCanonicalMaintenanceLease,
} from "../../../server/maintenance";
import {
  assertNoCanonicalDatabaseUsersSnapshot,
  assertNoActiveWorkSnapshot,
  assertExactReleaseDataFingerprintPolicy,
  assertReleaseCapacityPreflight,
  assertRollbackActiveReleaseMatchesReceipt,
  assertServiceIdentityUnchanged,
  applicationPointerMatches,
  committedTargetRuntimeIdentity,
  databaseMigrationRequired,
  ensureGuardedSourceRuntimeCommit,
  estimateReleaseCapacityRequirements,
  executePreparedDeploymentBoundary,
  executeWithFailClosedReleaseRecovery,
  FailClosedReleaseRecoveryError,
  legacyVerificationFromError,
  parseFunctionalReleaseArguments,
  reconcileStrandedDeployApplicationSwap,
  reconcileStrandedRollbackApplicationSwap,
  reconcileObservedReleasePointerDrift,
  reconcileStoppedServiceRuntimeLeaseAtBoundary,
  recoverFailedRollback,
  recoverFailedRelease,
  releaseStartupTimeoutMs,
  restoreDeploymentReceiptAfterFailedRollbackCommit,
  ProtectedLegacyInvariantError,
  requiresCanonicalMaintenanceBootstrap,
  restartUnchangedServiceAfterFailedStop,
  runFunctionalReleaseCli,
  runRequiredBounded,
  runMaintenanceThenServiceStart,
  safeErrorRecord,
  serviceCanRestartUnchanged,
  stopServiceWithGuardedFailedUnitNormalization,
  waitForExpectedTiScaleStartup,
  verifyReceiptPreviousApplicationBinding,
  withSecuredReleaseRehearsalWorkspace,
  type ReleasePointerSnapshot,
  type ServiceStopReleaseIdentity,
  type ServiceStopSnapshot,
  type TiScaleStartupObservation,
} from "../../../scripts/release/functional-release";
import {
  activateVerifiedStagedRecovery,
  assertStagedRecoveryResumeOnly,
  isResumeOnlyFinalizedReceipt,
  persistResumeOnlyFinalization,
  StagedRecoveryPostLegacyVerificationError,
  stagedRecoveryLegacyVerificationFromError,
  stagedRecoveryResumeDisposition,
  STAGED_RECOVERY_EXECUTE_DISABLED_MESSAGE,
} from "../../../scripts/release/activate-staged-recovery";
import {
  acquireSharedReleaseLock,
  ReleaseInterruptedError,
  ReleaseLockContentionError,
  withCooperativeReleaseSignals,
} from "../../../scripts/release/ReleaseExecutionBoundary";
import {
  assertVaultDatabaseSyncConsistency,
  canonicalVaultFingerprint,
  restoreVaultArchiveAtomically,
} from "../../../scripts/release/VaultReleasePrimitives";

const roots: string[] = [];

function makeWritable(path: string): void {
  if (!existsSync(path)) return;
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink()) return;
  if (metadata.isDirectory()) {
    chmodSync(path, 0o700);
    for (const name of readdirSync(path)) makeWritable(join(path, name));
  } else chmodSync(path, 0o600);
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    makeWritable(root);
    rmSync(root, { recursive: true, force: true });
  }
});

function fixture(): { workspace: string; source: string; releases: string } {
  const workspace = mkdtempSync(join(tmpdir(), "ti-scale-functional-release-"));
  roots.push(workspace);
  const source = join(workspace, "ti-scale-source");
  const releases = join(workspace, "ti-scale-server-releases");
  mkdirSync(join(source, "server"), { recursive: true });
  mkdirSync(join(source, "node_modules", ".bin"), { recursive: true });
  writeFileSync(join(source, "package.json"), "{\"name\":\"ti-scale-test\"}\n");
  writeFileSync(join(source, "server", "index.ts"), "export {};\n");
  writeFileSync(join(source, "node_modules", "tool.js"), "export {};\n");
  symlinkSync("../tool.js", join(source, "node_modules", ".bin", "tool"));
  return { workspace, source, releases };
}

/** The retired in-memory algorithm, retained only as a small-fixture oracle. */
function legacyReferenceDatabaseFingerprint(databasePath: string): string {
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  const hash = (value: string | Uint8Array): string =>
    createHash("sha256").update(value).digest("hex");
  const canonicalValue = (value: unknown): unknown => {
    if (typeof value === "bigint") return { bigint: value.toString() };
    if (value instanceof Uint8Array) return { blobSha256: hash(value), bytes: value.byteLength };
    return value;
  };
  try {
    database.exec("BEGIN DEFERRED");
    const schemaObjects = database.prepare(`
      SELECT type, name, tbl_name AS tableName, COALESCE(sql, '') AS sql
      FROM sqlite_master
      WHERE type IN ('table', 'index', 'trigger', 'view')
        AND name NOT LIKE 'sqlite_%'
      ORDER BY type, name
    `).all() as Array<{ type: string; name: string; tableName: string; sql: string }>;
    const aggregate = createHash("sha256");
    for (const schemaObject of schemaObjects) {
      aggregate
        .update("schema\0")
        .update(schemaObject.type).update("\0")
        .update(schemaObject.name).update("\0")
        .update(schemaObject.tableName).update("\0")
        .update(schemaObject.sql).update("\n");
    }
    for (const table of schemaObjects.filter((schemaObject) => schemaObject.type === "table")) {
      const quoted = `"${table.name.replaceAll('"', '""')}"`;
      const rows = database.prepare(`SELECT * FROM ${quoted}`).all() as Array<Record<string, unknown>>;
      const rowDigests = rows.map((row) => hash(JSON.stringify(
        Object.fromEntries(Object.keys(row).sort().map((key) => [key, canonicalValue(row[key])])),
      ))).sort();
      aggregate.update("rows\0").update(table.name).update("\0");
      for (const rowDigest of rowDigests) aggregate.update(rowDigest).update("\n");
    }
    const fingerprint = aggregate.digest("hex");
    database.exec("COMMIT");
    return fingerprint;
  } catch (error) {
    if (database.inTransaction) database.exec("ROLLBACK");
    throw error;
  } finally {
    database.close();
  }
}

describe("functional release CLI boundary", () => {
  test("rejects the retired backup-capable command before touching any supplied path", async () => {
    const root = fixture().workspace;
    const forbiddenPath = join(root, "must-not-be-created");

    await expect(runFunctionalReleaseCli([
      "deploy",
      "--execute",
      "--release-id",
      "retired-no-copy-path",
      "--source-root",
      forbiddenPath,
    ])).rejects.toThrow(
      "Backup-capable functional release is disabled by the operator no-backup policy",
    );
    expect(existsSync(forbiddenPath)).toBe(false);
  });

  test("requires an active, non-negative, POSIX-bounded committed target runtime identity", () => {
    expect(committedTargetRuntimeIdentity({
      serviceIntent: "active",
      databaseOwnerUid: 1001,
      databaseOwnerGid: 1002,
      databaseMode: 0o600,
    }, "Committed target")).toEqual({
      databaseOwnerUid: 1001,
      databaseOwnerGid: 1002,
      databaseMode: 0o600,
    });
    expect(() => committedTargetRuntimeIdentity({
      serviceIntent: "inactive",
      databaseOwnerUid: 1001,
      databaseOwnerGid: 1002,
      databaseMode: 0o600,
    }, "Committed target")).toThrow("service intent is unsupported");
    expect(() => committedTargetRuntimeIdentity({
      serviceIntent: "active",
      databaseOwnerUid: -1,
      databaseOwnerGid: 1002,
      databaseMode: 0o600,
    }, "Committed target")).toThrow("database owner UID is missing or invalid");
    expect(() => committedTargetRuntimeIdentity({
      serviceIntent: "active",
      databaseOwnerUid: 1001,
      databaseOwnerGid: 1002,
      databaseMode: 0o1000,
    }, "Committed target")).toThrow("database mode is invalid");
  });

  test("skips migration for an equal schema and refuses a database downgrade", () => {
    expect(databaseMigrationRequired(36, 37)).toBe(true);
    expect(databaseMigrationRequired(37, 37)).toBe(false);
    expect(() => databaseMigrationRequired(38, 37)).toThrow("downgrade is refused");
    expect(() => databaseMigrationRequired(-1, 37)).toThrow("non-negative safe integer");
    expect(() => databaseMigrationRequired(37, Number.NaN)).toThrow("non-negative safe integer");
  });

  test("models every durable database copy while keeping the restore rehearsal disposable", () => {
    const gibibyte = 1024n * 1024n * 1024n;
    const migration = estimateReleaseCapacityRequirements({
      databaseBytes: 6n * gibibyte,
      sourceArchiveInputBytes: 1n * gibibyte,
      vaultArchiveInputBytes: 2n * gibibyte,
      schemaMigrationRequired: true,
    });
    expect(migration.persistentDatabaseCopies).toBe(3);
    expect(migration.persistentBytes).toBeGreaterThan(21n * gibibyte);
    expect(migration.rehearsalBytes).toBeGreaterThan(6n * gibibyte);
    expect(migration.rehearsalBytes).toBeLessThan(7n * gibibyte);

    const noMigration = estimateReleaseCapacityRequirements({
      databaseBytes: 6n * gibibyte,
      sourceArchiveInputBytes: 1n * gibibyte,
      vaultArchiveInputBytes: 2n * gibibyte,
      schemaMigrationRequired: false,
    });
    expect(noMigration.persistentDatabaseCopies).toBe(2);
    expect(migration.persistentBytes - noMigration.persistentBytes).toBeGreaterThan(6n * gibibyte);
  });

  test("checks persistent and rehearsal capacity independently and aggregates a shared filesystem peak", () => {
    const gibibyte = 1024n * 1024n * 1024n;
    const requirements = estimateReleaseCapacityRequirements({
      databaseBytes: 2n * gibibyte,
      sourceArchiveInputBytes: gibibyte / 2n,
      vaultArchiveInputBytes: gibibyte / 2n,
      schemaMigrationRequired: false,
    });
    const persistent = {
      path: "/persistent",
      device: "8:1",
      availableBytes: requirements.persistentBytes,
    };
    const rehearsal = {
      path: "/rehearsal",
      device: "0:42",
      availableBytes: requirements.rehearsalBytes,
    };
    expect(() => assertReleaseCapacityPreflight(requirements, persistent, rehearsal)).not.toThrow();
    expect(() => assertReleaseCapacityPreflight(requirements, {
      ...persistent,
      availableBytes: requirements.persistentBytes - 1n,
    }, rehearsal)).toThrow("persistent backup filesystem");
    expect(() => assertReleaseCapacityPreflight(requirements, persistent, {
      ...rehearsal,
      availableBytes: requirements.rehearsalBytes - 1n,
    })).toThrow("rehearsal filesystem");

    // Each individual requirement fits, but their simultaneous peak does not.
    expect(() => assertReleaseCapacityPreflight(requirements, {
      ...persistent,
      availableBytes: requirements.persistentBytes,
    }, {
      ...rehearsal,
      device: persistent.device,
      availableBytes: requirements.persistentBytes,
    })).toThrow("shared persistent/rehearsal filesystem");
    expect(() => assertReleaseCapacityPreflight(requirements, {
      ...persistent,
      availableBytes: requirements.persistentBytes + requirements.rehearsalBytes,
    }, {
      ...rehearsal,
      device: persistent.device,
      availableBytes: requirements.persistentBytes + requirements.rehearsalBytes,
    })).not.toThrow();
  });

  test("uses an owner-only injected rehearsal root and cleans it on success and failure", async () => {
    const { workspace } = fixture();
    const base = join(workspace, "rehearsal-base");
    mkdirSync(base, { mode: 0o700 });
    let successfulWorkspace = "";
    await withSecuredReleaseRehearsalWorkspace((temporary) => {
      successfulWorkspace = temporary;
      const metadata = statSync(temporary);
      expect(metadata.isDirectory()).toBe(true);
      expect(metadata.mode & 0o777).toBe(0o700);
      writeFileSync(join(temporary, "restore.sqlite"), "temporary restore image\n", { mode: 0o600 });
    }, { baseDirectory: base });
    expect(existsSync(successfulWorkspace)).toBe(false);

    let failedWorkspace = "";
    await expect(withSecuredReleaseRehearsalWorkspace((temporary) => {
      failedWorkspace = temporary;
      writeFileSync(join(temporary, "restore.sqlite"), "partial restore image\n", { mode: 0o600 });
      throw new Error("injected rehearsal failure");
    }, { baseDirectory: base })).rejects.toThrow("injected rehearsal failure");
    expect(existsSync(failedWorkspace)).toBe(false);
    expect(readdirSync(base)).toEqual([]);
  });

  test("rejects symlink rehearsal roots and removes child links without following them", async () => {
    const { workspace } = fixture();
    const base = join(workspace, "rehearsal-base");
    const alias = join(workspace, "rehearsal-alias");
    const protectedFile = join(workspace, "protected.txt");
    mkdirSync(base, { mode: 0o700 });
    symlinkSync(base, alias);
    await expect(withSecuredReleaseRehearsalWorkspace(() => undefined, {
      baseDirectory: alias,
    })).rejects.toThrow("non-symlink directory");

    writeFileSync(protectedFile, "must survive cleanup\n", { mode: 0o600 });
    let temporary = "";
    await expect(withSecuredReleaseRehearsalWorkspace((workspacePath) => {
      temporary = workspacePath;
      symlinkSync(protectedFile, join(workspacePath, "unexpected-link"));
    }, { baseDirectory: base })).rejects.toThrow("non-regular entry");
    expect(existsSync(temporary)).toBe(false);
    expect(readFileSync(protectedFile, "utf8")).toBe("must survive cleanup\n");
  });

  test("requires an independently captured healthy post-release legacy identity to match", () => {
    const before = {
      activeState: "active",
      mainPid: 31_311,
      invocationId: "legacy-invocation-before",
      healthStatus: 200,
      semanticStatus: "ok",
    } as const;
    const after = { ...before };

    expect(assertServiceIdentityUnchanged(before, after, "ChillsPwn on port 3131")).toEqual(after);
    expect(() => assertServiceIdentityUnchanged(before, {
      ...after,
      mainPid: after.mainPid + 1,
    }, "ChillsPwn on port 3131")).toThrow("changed during the Ti-Scale release");
    expect(() => assertServiceIdentityUnchanged(before, {
      ...after,
      invocationId: "legacy-invocation-after",
    }, "ChillsPwn on port 3131")).toThrow("changed during the Ti-Scale release");
    expect(() => assertServiceIdentityUnchanged(before, {
      ...after,
      healthStatus: 503,
      semanticStatus: "degraded",
    }, "ChillsPwn on port 3131")).toThrow("not healthy enough");
  });

  test("requires one explicit mode and an exact execute confirmation", () => {
    expect(parseFunctionalReleaseArguments([
      "deploy", "--dry-run", "--release-id", "candidate-1",
    ], "/tmp/source")).toMatchObject({
      command: "deploy",
      mode: "dry-run",
      releaseId: "candidate-1",
      sourceRoot: "/tmp/source",
    });
    expect(() => parseFunctionalReleaseArguments([
      "deploy", "--release-id", "candidate-1",
    ])).toThrow("exactly one");
    expect(() => parseFunctionalReleaseArguments([
      "deploy", "--execute", "--release-id", "candidate-1",
    ])).toThrow("requires --confirm");
    expect(() => parseFunctionalReleaseArguments([
      "rollback", "--dry-run", "--receipt", "/tmp/receipt.json", "--confirm", "candidate-1",
    ])).toThrow("valid only with --execute");
  });

  test("legacy staged activation is resume-only and cannot enter a new mutation path", async () => {
    expect(() => assertStagedRecoveryResumeOnly(true)).not.toThrow();
    expect(() => assertStagedRecoveryResumeOnly(false)).toThrow(
      STAGED_RECOVERY_EXECUTE_DISABLED_MESSAGE,
    );
    expect(STAGED_RECOVERY_EXECUTE_DISABLED_MESSAGE).toContain(
      "forward-only no-backup controller",
    );
    await expect(activateVerifiedStagedRecovery([
      "--release-id", "disabled-execute-path",
      "--execute", "yes",
      "--confirm", "disabled-execute-path",
    ])).rejects.toThrow(STAGED_RECOVERY_EXECUTE_DISABLED_MESSAGE);
  });

  test("resume-only finalization repairs a checksum after a crash following receipt commit", () => {
    const { workspace } = fixture();
    const directory = join(workspace, "receipt");
    const receiptPath = join(directory, "activation-receipt.json");
    const checksumPath = join(directory, "activation-receipt.sha256");
    mkdirSync(directory, { recursive: true });
    const pending: Record<string, unknown> = {
      schemaVersion: "ti-scale.staged-recovery-activation.v1",
      releaseId: "resume-fault",
      status: "activated_service_pending",
      database: { targetSchema: 37 },
      legacyBefore: {
        state: "active",
        pid: 31,
        invocationId: "legacy",
        healthStatus: 200,
        semanticStatus: "ok",
      },
    };
    expect(stagedRecoveryResumeDisposition(pending, "resume-fault")).toBe("pending_finalization");
    expect(() => stagedRecoveryResumeDisposition({ ...pending, status: "verified" }, "resume-fault"))
      .toThrow("Only an exact activated_service_pending receipt");
    writeFileSync(receiptPath, `${JSON.stringify(pending)}\n`, { mode: 0o600 });
    const finalizedFields = {
      deployedAt: "2026-07-21T00:00:00.000Z",
      health: {
        status: "healthy",
        database: { healthy: true, currentMigration: 37 },
      },
      database: {
        targetSchema: 37,
        integrityAfter: { quickCheck: "ok", foreignKeyViolations: 0 },
      },
      legacyAfter: {
        state: "active",
        pid: 31,
        invocationId: "legacy",
        healthStatus: 200,
        semanticStatus: "ok",
      },
      tiScaleAfter: {
        state: "active",
        pid: 32,
        invocationId: "ti-scale",
        healthStatus: 200,
        semanticStatus: "healthy",
      },
    };

    expect(() => persistResumeOnlyFinalization({
      receiptPath,
      receipt: pending,
      releaseId: "resume-fault",
      finalizedFields,
      beforeChecksumWrite: () => { throw new Error("simulated crash before checksum rename"); },
    })).toThrow("simulated crash before checksum rename");
    expect(existsSync(checksumPath)).toBe(false);
    const committed = JSON.parse(readFileSync(receiptPath, "utf8")) as Record<string, unknown>;
    expect(isResumeOnlyFinalizedReceipt(committed, "resume-fault")).toBe(true);
    expect(stagedRecoveryResumeDisposition(committed, "resume-fault")).toBe("checksum_repair");
    expect(() => persistResumeOnlyFinalization({
      receiptPath,
      receipt: committed,
      releaseId: "resume-fault",
      finalizedFields: {},
    })).toThrow("requires recomputed current health");
    expect(existsSync(checksumPath)).toBe(false);
    expect(JSON.parse(readFileSync(receiptPath, "utf8"))).toEqual(committed);

    const recomputedFields = {
      ...finalizedFields,
      health: {
        status: "healthy",
        checkedAt: "2026-07-21T00:00:05.000Z",
        database: { healthy: true, currentMigration: 37 },
      },
      tiScaleAfter: {
        state: "active",
        pid: 33,
        invocationId: "ti-scale-current",
        healthStatus: 200,
        semanticStatus: "healthy",
      },
    };
    const repaired = persistResumeOnlyFinalization({
      receiptPath,
      receipt: committed,
      releaseId: "resume-fault",
      finalizedFields: recomputedFields,
    });
    expect(repaired.checksumRepaired).toBe(true);
    expect(readFileSync(checksumPath, "utf8")).toBe(
      `${repaired.receiptSha256}  activation-receipt.json\n`,
    );
    expect(JSON.parse(readFileSync(receiptPath, "utf8"))).toMatchObject(recomputedFields);
    expect(JSON.parse(readFileSync(receiptPath, "utf8"))).not.toEqual(committed);
  });

  test("resume-only finalized receipts reject truthy but semantically invalid evidence", () => {
    const exact: Record<string, unknown> = {
      schemaVersion: "ti-scale.staged-recovery-activation.v1",
      releaseId: "semantic-evidence",
      status: "deployed",
      resumedFromPendingReceipt: true,
      resumeOnlyFinalization: true,
      deployedAt: "2026-07-21T00:00:00.000Z",
      health: {
        status: "healthy",
        database: { healthy: true, currentMigration: 37 },
      },
      database: {
        targetSchema: 37,
        integrityAfter: { quickCheck: "ok", foreignKeyViolations: 0 },
      },
      legacyBefore: {
        state: "active", pid: 31, invocationId: "legacy",
        healthStatus: 200, semanticStatus: "ok",
      },
      legacyAfter: {
        state: "active", pid: 31, invocationId: "legacy",
        healthStatus: 200, semanticStatus: "ok",
      },
      tiScaleAfter: {
        state: "active", pid: 32, invocationId: "ti-scale",
        healthStatus: 200, semanticStatus: "healthy",
      },
    };
    expect(isResumeOnlyFinalizedReceipt(exact, "semantic-evidence")).toBe(true);
    const malformed = [
      { ...exact, health: "truthy" },
      { ...exact, health: { status: "degraded", database: { healthy: true, currentMigration: 37 } } },
      { ...exact, legacyAfter: { state: "active" } },
      { ...exact, legacyAfter: { ...(exact.legacyAfter as object), pid: 99 } },
      { ...exact, tiScaleAfter: [] },
      { ...exact, tiScaleAfter: { ...(exact.tiScaleAfter as object), healthStatus: 503 } },
      { ...exact, database: { ...(exact.database as object), targetSchema: 38 } },
      { ...exact, deployedAt: "truthy" },
    ];
    for (const receipt of malformed) {
      expect(isResumeOnlyFinalizedReceipt(receipt, "semantic-evidence")).toBe(false);
      expect(() => stagedRecoveryResumeDisposition(receipt, "semantic-evidence"))
        .toThrow("Only an exact activated_service_pending receipt");
    }
  });

  test("post-verification failures retain truthful legacy verification evidence", () => {
    const checksumFailure = new StagedRecoveryPostLegacyVerificationError(
      new Error("simulated checksum failure"),
    );
    expect(checksumFailure.message).toBe("simulated checksum failure");
    expect(stagedRecoveryLegacyVerificationFromError(checksumFailure)).toBe("verified_unchanged");
    expect(stagedRecoveryLegacyVerificationFromError(
      new Error("outer failure", { cause: checksumFailure }),
    )).toBe("verified_unchanged");
    expect(stagedRecoveryLegacyVerificationFromError(new Error("pre-verification failure")))
      .toBe("not_verified_on_failure");
  });

  test("durable atomic receipts sync bytes before rename and the parent directory after rename", () => {
    const { workspace } = fixture();
    const path = join(workspace, "durable", "receipt.json");
    const phases: DurableAtomicWritePhase[] = [];
    writeDurableFileAtomically(path, "first\n", {
      onPhase: (phase) => { phases.push(phase); },
    });
    expect(phases).toEqual([
      "temporary_written",
      "temporary_synced",
      "renamed",
      "directory_synced",
    ]);
    expect(readFileSync(path, "utf8")).toBe("first\n");

    expect(() => writeDurableFileAtomically(path, "committed-before-dir-sync\n", {
      onPhase: (phase) => {
        if (phase === "renamed") throw new Error("simulated crash after rename");
      },
    })).toThrow("simulated crash after rename");
    expect(readFileSync(path, "utf8")).toBe("committed-before-dir-sync\n");
    writeDurableFileAtomically(path, "repaired\n");
    expect(readFileSync(path, "utf8")).toBe("repaired\n");
  });

  test("durably publishes every missing first-install ancestor before its descendants", () => {
    const { workspace } = fixture();
    const target = join(workspace, "first", "second", "transaction-bundle");
    const events: string[] = [];
    createDirectoryDurably(target, {
      mode: 0o750,
      onPhase: (phase: DurableDirectoryCreatePhase, directory: string) => {
        events.push(`${phase}:${directory.slice(workspace.length + 1)}`);
      },
    });
    expect(events).toEqual([
      "directory_created:first",
      "directory_synced:first",
      "parent_synced:first",
      "directory_created:first/second",
      "directory_synced:first/second",
      "parent_synced:first/second",
      "directory_created:first/second/transaction-bundle",
      "directory_synced:first/second/transaction-bundle",
      "parent_synced:first/second/transaction-bundle",
    ]);
    expect(lstatSync(target).isDirectory()).toBe(true);
  });

  test("publishes a prepared directory atomically and syncs the final parent", () => {
    const { workspace } = fixture();
    const staging = join(workspace, ".transaction-journal.opening");
    const destination = join(workspace, "transaction-journal");
    mkdirSync(staging);
    writeFileSync(join(staging, "00000000-record.json"), "opened\n");
    const phases: DurableDirectoryRenamePhase[] = [];
    renameDirectoryDurably(staging, destination, {
      onPhase: (phase) => { phases.push(phase); },
    });
    expect(phases).toEqual(["source_synced", "renamed", "parent_synced"]);
    expect(existsSync(staging)).toBe(false);
    expect(readFileSync(join(destination, "00000000-record.json"), "utf8")).toBe("opened\n");
  });

  test("shared flock excludes concurrent release mutation and is released by a crashed owner", async () => {
    const { workspace } = fixture();
    const lockPath = join(workspace, "release.lock");
    const readyPath = join(workspace, "child-ready");
    const first = acquireSharedReleaseLock(lockPath, "first-owner");
    try {
      expect(() => acquireSharedReleaseLock(lockPath, "contender"))
        .toThrow(ReleaseLockContentionError);
    } finally { first.release(); }
    const afterRelease = acquireSharedReleaseLock(lockPath, "after-release");
    afterRelease.release();

    const modulePath = join(process.cwd(), "scripts/release/ReleaseExecutionBoundary.ts");
    const child = Bun.spawn([process.execPath, "--eval", `
      import { writeFileSync } from "node:fs";
      import { acquireSharedReleaseLock } from ${JSON.stringify(modulePath)};
      const lock = acquireSharedReleaseLock(${JSON.stringify(lockPath)}, "crash-owner");
      writeFileSync(${JSON.stringify(readyPath)}, "ready\\n");
      await Bun.sleep(60_000);
      lock.release();
    `], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
    try {
      const deadline = performance.now() + 2_000;
      while (!existsSync(readyPath) && performance.now() < deadline) await Bun.sleep(10);
      expect(existsSync(readyPath)).toBe(true);
      expect(() => acquireSharedReleaseLock(lockPath, "crash-contender"))
        .toThrow(ReleaseLockContentionError);
      child.kill("SIGKILL");
      await child.exited;
      const afterCrash = acquireSharedReleaseLock(lockPath, "after-crash");
      afterCrash.release();
    } finally {
      try { child.kill("SIGKILL"); } catch { /* already terminal */ }
      try { await child.exited; } catch { /* already terminal */ }
    }
  });

  test("a signal after the last successful checkpoint does not retroactively fail success", async () => {
    const signals = new EventEmitter();
    const result = await withCooperativeReleaseSignals(async (interruption) => {
      interruption.throwIfAborted();
      signals.emit("SIGTERM");
      return "durably-committed";
    }, signals);
    expect(result).toBe("durably-committed");
  });

  test("bootstraps the lease schema only for a pre-v35 database and fails closed on inconsistent state", () => {
    expect(requiresCanonicalMaintenanceBootstrap(33, 35, false)).toBe(true);
    expect(requiresCanonicalMaintenanceBootstrap(34, 36, false)).toBe(true);
    expect(requiresCanonicalMaintenanceBootstrap(35, 35, true)).toBe(false);
    expect(() => requiresCanonicalMaintenanceBootstrap(35, 35, false)).toThrow(
      "reports the lease migration",
    );
    expect(() => requiresCanonicalMaintenanceBootstrap(34, 34, false)).toThrow(
      "cannot install",
    );
  });

  test("fails closed when any process still has the canonical database open", () => {
    expect(() => assertNoCanonicalDatabaseUsersSnapshot([])).not.toThrow();
    expect(() => assertNoCanonicalDatabaseUsersSnapshot([42, 7, 42])).toThrow(
      "pid:7, pid:42",
    );
  });

  test("a pre-v35 bootstrap acquires maintenance before mutation and releases it before service startup", async () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "bootstrap.sqlite");
    const bootstrapDatabase = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(bootstrapDatabase, DATABASE_MIGRATIONS.slice(0, 34));
      expect(CanonicalDatabaseLeaseService.schemaAvailable(bootstrapDatabase)).toBe(false);
      expect(requiresCanonicalMaintenanceBootstrap(34, 35, false)).toBe(true);
      migrateDatabase(bootstrapDatabase);
      expect(CanonicalDatabaseLeaseService.schemaAvailable(bootstrapDatabase)).toBe(true);
    } finally {
      bootstrapDatabase.close();
    }

    const maintenanceDatabase = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    const writerDatabase = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    const order: string[] = [];
    try {
      await runMaintenanceThenServiceStart(async () => {
        await withCanonicalMaintenanceLease(maintenanceDatabase, {
          ownerId: "release:test",
          operation: "bootstrap-test",
        }, async () => {
          order.push("maintenance-active");
          const writers = new CanonicalDatabaseLeaseService(writerDatabase);
          expect(() => writers.acquireWriter({
            ownerId: "service:test",
            operation: "standalone-service-runtime",
          })).toThrow(CanonicalDatabaseLeaseConflictError);
          order.push("writer-blocked");
        });
        order.push("maintenance-released");
      }, () => {
        order.push("service-start");
        const writers = new CanonicalDatabaseLeaseService(writerDatabase);
        const writer = writers.acquireWriter({
          ownerId: "service:test",
          operation: "standalone-service-runtime",
        });
        order.push("writer-acquired");
        writers.release(writer);
      });
    } finally {
      writerDatabase.close();
      maintenanceDatabase.close();
    }
    expect(order).toEqual([
      "maintenance-active",
      "writer-blocked",
      "maintenance-released",
      "service-start",
      "writer-acquired",
    ]);
  });

  test("stages .env.example but excludes secret env, git, artifact, and test-result trees", async () => {
    const { source, releases } = fixture();
    writeFileSync(join(source, ".env.example"), "SAFE_EXAMPLE=true\n");
    writeFileSync(join(source, ".env.production"), "DO_NOT_COPY=secret\n");
    for (const directory of [".git", ".artifacts", "test-results"] as const) {
      mkdirSync(join(source, directory), { recursive: true });
      writeFileSync(join(source, directory, "excluded.txt"), "excluded\n");
    }

    const release = await stageServerRelease({
      sourceRoot: source,
      releaseRoot: releases,
      releaseId: "candidate-env",
      createdAt: "2026-07-19T00:00:00.000Z",
    });

    expect(readFileSync(join(release.releaseDirectory, ".env.example"), "utf8")).toContain("SAFE_EXAMPLE");
    expect(existsSync(join(release.releaseDirectory, ".env.production"))).toBe(false);
    expect(existsSync(join(release.releaseDirectory, ".git"))).toBe(false);
    expect(existsSync(join(release.releaseDirectory, ".artifacts"))).toBe(false);
    expect(existsSync(join(release.releaseDirectory, "test-results"))).toBe(false);
    expect(release.manifest.entries.some((entry) => entry.path === "node_modules/.bin/tool" && entry.kind === "symlink")).toBe(true);
  });

  test("detects post-stage tampering and rejects a source symlink that escapes the release", async () => {
    const first = fixture();
    const release = await stageServerRelease({
      sourceRoot: first.source,
      releaseRoot: first.releases,
      releaseId: "candidate-tamper",
    });
    const rollbackTreeIdentity = await canonicalApplicationTreeFingerprint(release.releaseDirectory);
    await expect(assertApplicationTreeFingerprint(release.releaseDirectory, rollbackTreeIdentity)).resolves.toBeUndefined();
    const index = join(release.releaseDirectory, "server", "index.ts");
    chmodSync(index, 0o644);
    writeFileSync(index, "tampered\n");
    await expect(verifyServerRelease(release.releaseDirectory, release.releaseId, release.manifestSha256))
      .rejects.toThrow("does not match");
    await expect(assertApplicationTreeFingerprint(release.releaseDirectory, rollbackTreeIdentity))
      .rejects.toThrow("checksum-bound identity");

    const second = fixture();
    symlinkSync("../../../outside", join(second.source, "server", "escape"));
    await expect(stageServerRelease({
      sourceRoot: second.source,
      releaseRoot: second.releases,
      releaseId: "candidate-escape",
    })).rejects.toThrow("escapes its root");
  });

  test("publishes a self-excluding checksum manifest and catches changed backup content", async () => {
    const { workspace } = fixture();
    const bundle = join(workspace, "bundle");
    mkdirSync(bundle);
    writeFileSync(join(bundle, "database.sqlite"), "database snapshot\n");
    writeFileSync(join(bundle, "vault.tar.gz"), "vault snapshot\n");
    const phases: ChecksumManifestPublicationPhase[] = [];
    const manifest = await writeAndVerifyChecksumManifest(
      bundle,
      ["database.sqlite", "vault.tar.gz"],
      { onPhase: (phase) => { phases.push(phase); } },
    );
    expect(phases).toEqual([
      "payload_synced:database.sqlite",
      "payload_synced:vault.tar.gz",
      "payload_directory_synced",
      "manifest_temporary_written",
      "manifest_temporary_synced",
      "manifest_renamed",
      "manifest_directory_synced",
    ]);
    expect(Object.keys(manifest.entries)).toEqual(["database.sqlite", "vault.tar.gz"]);
    expect(readFileSync(manifest.path, "utf8")).not.toContain("SHA256SUMS");
    expect(Object.keys(await verifyChecksumManifest(bundle))).toHaveLength(2);
    writeFileSync(join(bundle, "vault.tar.gz"), "changed\n");
    await expect(verifyChecksumManifest(bundle)).rejects.toThrow("verification failed");
  });

  test("fingerprints exact managed Vault state and verifies synced database rows against note bytes", async () => {
    const { workspace } = fixture();
    const vaultRoot = join(workspace, "vaults");
    const connectedVault = join(vaultRoot, "Attack-Knowledge-Vault");
    const notePath = join(connectedVault, "Techniques", "service-path.md");
    mkdirSync(join(connectedVault, "Techniques"), { recursive: true });
    const note = "---\nid: technique-service-path\n---\nVerified path\n";
    writeFileSync(notePath, note, { mode: 0o600 });
    const first = await canonicalVaultFingerprint(vaultRoot);
    expect(await canonicalVaultFingerprint(vaultRoot)).toBe(first);
    writeFileSync(notePath, `${note}Changed\n`, { mode: 0o600 });
    expect(await canonicalVaultFingerprint(vaultRoot)).not.toBe(first);
    writeFileSync(notePath, note, { mode: 0o600 });

    const databasePath = join(workspace, "vault-consistency.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    const now = "2026-07-21T00:00:00.000Z";
    const hash = createHash("sha256").update(note).digest("hex");
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO vault_connections (
          id, vault_path, display_name, status, sync_scope_json,
          permission_granted_at, created_at, updated_at
        ) VALUES (?, ?, ?, 'connected', '{}', ?, ?, ?)
      `).run("vault-release-test", connectedVault, "Release Vault", now, now, now);
      database.prepare(`
        INSERT INTO vault_sync_state (
          id, connection_id, relative_path, database_version,
          vault_content_hash, database_content_hash, status,
          last_scanned_at, last_synced_at
        ) VALUES (?, ?, ?, 1, ?, ?, 'synced', ?, ?)
      `).run("vault-sync-release-test", "vault-release-test", "Techniques/service-path.md", hash, hash, now, now);
    } finally { database.close(); }

    expect(await assertVaultDatabaseSyncConsistency(databasePath, vaultRoot)).toEqual({
      connections: 1,
      syncedFiles: 1,
    });
    writeFileSync(notePath, "tampered\n", { mode: 0o600 });
    await expect(assertVaultDatabaseSyncConsistency(databasePath, vaultRoot))
      .rejects.toThrow("disagree with canonical database state");
  });

  test("rejects Vault archive restore before resolving or creating paths", async () => {
    const { workspace } = fixture();
    const archive = join(workspace, "missing-vault.tar.gz");
    const liveVault = join(workspace, "missing-live-vault");
    expect(existsSync(archive)).toBe(false);
    expect(existsSync(liveVault)).toBe(false);

    await expect(restoreVaultArchiveAtomically({
      archivePath: archive,
      vaultRoot: liveVault,
      expectedFingerprint: "0".repeat(64),
      swapId: "disabled",
    })).rejects.toThrow(
      "Vault archive restore is disabled by operator no-backup policy",
    );

    expect(existsSync(archive)).toBe(false);
    expect(existsSync(liveVault)).toBe(false);
  });

  test("uses an atomic exchange for the first directory-to-release handoff and a symlink rollback", () => {
    const { workspace } = fixture();
    const application = join(workspace, "ti-scale");
    const next = join(workspace, "releases", "next");
    const previous = join(workspace, "releases", "previous");
    mkdirSync(application);
    mkdirSync(next, { recursive: true });
    writeFileSync(join(application, "old.txt"), "old\n");
    writeFileSync(join(next, "new.txt"), "new\n");

    const activated = exchangeApplicationTarget({
      applicationPath: application,
      newTarget: next,
      previousDirectoryArchive: previous,
      swapName: "candidate-swap",
    });
    expect(lstatSync(application).isSymbolicLink()).toBe(true);
    expect(activated.previousKind).toBe("directory");
    expect(readFileSync(join(previous, "old.txt"), "utf8")).toBe("old\n");

    const rolledBack = exchangeApplicationTarget({
      applicationPath: application,
      newTarget: previous,
      previousDirectoryArchive: join(workspace, "unused"),
      swapName: "candidate-rollback",
    });
    expect(rolledBack.previousKind).toBe("symlink");
    expect(readFileSync(join(application, "old.txt"), "utf8")).toBe("old\n");
  });

  test("rejects stranded rollback archive reconciliation before touching paths", () => {
    const { workspace } = fixture();
    const applicationPath = join(workspace, "missing-live");
    const displacedArchive = join(workspace, "missing-archive");
    const expected = {
      kind: "symlink",
      target: join(workspace, "missing-target"),
      device: "not-used-for-symlink",
      inode: "not-used-for-symlink",
    } as const;

    expect(() => reconcileStrandedRollbackApplicationSwap({
      applicationPath,
      expected,
      candidatePaths: [displacedArchive],
      swapName: "disabled",
      serverReleaseRoot: join(workspace, "missing-releases"),
    })).toThrow(
      "Rollback application archive reconciliation is disabled by operator no-backup policy",
    );
    expect(existsSync(applicationPath)).toBe(false);
    expect(existsSync(displacedArchive)).toBe(false);
  });

  test("removes only a stranded journal-bound deploy target after exact source recovery", async () => {
    const { workspace } = fixture();
    const serverReleaseRoot = join(workspace, "releases");
    const target = join(serverReleaseRoot, "candidate");
    const applicationPath = join(workspace, "ti-scale-live");
    const swapName = "deploy-forward";
    const stranded = join(workspace, `.ti-scale-live.${swapName}.swap`);
    mkdirSync(applicationPath);
    mkdirSync(target, { recursive: true });
    writeFileSync(join(applicationPath, "source.txt"), "source\n");
    writeFileSync(join(target, "target.txt"), "target\n");
    const sourceMetadata = lstatSync(applicationPath, { bigint: true });
    const expectedSource = {
      kind: "directory",
      target: applicationPath,
      device: sourceMetadata.dev.toString(),
      inode: sourceMetadata.ino.toString(),
    } as const;
    const expectedTarget = {
      kind: "symlink",
      target,
      device: "not-used-for-symlink",
      inode: "not-used-for-symlink",
    } as const;
    const expectedSourceTreeSha256 = await canonicalApplicationTreeFingerprint(applicationPath);
    symlinkSync(target, stranded);

    await expect(reconcileStrandedDeployApplicationSwap({
      applicationPath,
      expectedSource,
      expectedSourceTreeSha256,
      expectedTarget,
      swapName,
      serverReleaseRoot,
    })).resolves.toBe("removed_target_symlink");
    expect(existsSync(stranded)).toBe(false);
    expect(readFileSync(join(applicationPath, "source.txt"), "utf8")).toBe("source\n");

    await expect(reconcileStrandedDeployApplicationSwap({
      applicationPath,
      expectedSource,
      expectedSourceTreeSha256,
      expectedTarget,
      swapName,
      serverReleaseRoot,
    })).resolves.toBe("absent");

    const otherTarget = join(serverReleaseRoot, "other");
    mkdirSync(otherTarget);
    symlinkSync(otherTarget, stranded);
    await expect(reconcileStrandedDeployApplicationSwap({
      applicationPath,
      expectedSource,
      expectedSourceTreeSha256,
      expectedTarget,
      swapName,
      serverReleaseRoot,
    })).rejects.toThrow("does not match the journal-bound target release");
    expect(existsSync(stranded)).toBe(true);
  });

  test("recognizes the moved first-release directory by dev/inode rather than its archive path", () => {
    const original = {
      kind: "directory",
      target: "/opt/ti-scale",
      device: "2049",
      inode: "88117",
    } as const;
    expect(applicationPointerMatches({
      ...original,
      target: "/opt/ti-scale-server-releases/releases/previous-first-release",
    }, original)).toBe(true);
    expect(applicationPointerMatches({
      ...original,
      target: "/opt/ti-scale-server-releases/releases/previous-first-release",
      inode: "88118",
    }, original)).toBe(false);
    expect(applicationPointerMatches({
      kind: "symlink",
      target: "/opt/ti-scale-server-releases/releases/candidate",
      device: "ignored",
      inode: "ignored",
    }, {
      kind: "symlink",
      target: "/opt/ti-scale-server-releases/releases/current",
      device: "ignored",
      inode: "ignored",
    })).toBe(false);
  });

  test("terminal receipt verification accepts an exact first directory deployment rollback at the live path", async () => {
    const { workspace } = fixture();
    const application = join(workspace, "ti-scale");
    const serverReleaseRoot = join(workspace, "releases");
    const next = join(serverReleaseRoot, "next");
    const previous = join(serverReleaseRoot, "previous-first-release");
    const displacedSymlink = join(workspace, "deployed-application-link");
    mkdirSync(application);
    mkdirSync(next, { recursive: true });
    writeFileSync(join(application, "old.txt"), "old\n");
    writeFileSync(join(next, "new.txt"), "new\n");

    const original = lstatSync(application, { bigint: true });
    const originalTreeSha256 = await canonicalApplicationTreeFingerprint(application);
    const binding = {
      applicationKind: "directory",
      applicationTarget: previous,
      applicationDevice: original.dev.toString(),
      applicationInode: original.ino.toString(),
      applicationTreeSha256: originalTreeSha256,
      staticPointer: {
        schemaVersion: "ti-scale.static-artifact-pointer.v1",
        scope: "v2_static_artifact_pointer_only",
        generation: 1,
        activeReleaseId: "previous-static",
        activeManifestSha256: "previous-static-manifest",
        previousReleaseId: null,
        previousManifestSha256: null,
        activatedAt: "2026-07-22T00:00:00.000Z",
      },
    } as const;

    exchangeApplicationTarget({
      applicationPath: application,
      newTarget: next,
      previousDirectoryArchive: previous,
      swapName: "first-directory-deployment",
    });
    expect(lstatSync(application).isSymbolicLink()).toBe(true);
    await expect(verifyReceiptPreviousApplicationBinding(binding, {
      serverReleaseRoot,
    })).resolves.toBeUndefined();

    // Model the committed result of restoreExactApplicationPointer: the exact
    // preserved inode is back at the live name and the displaced release link
    // has been removed from the now-vacated archive name.
    renameSync(application, displacedSymlink);
    renameSync(previous, application);
    unlinkSync(displacedSymlink);
    const restored = lstatSync(application, { bigint: true });
    expect(restored.isDirectory()).toBe(true);
    expect(restored.dev.toString()).toBe(binding.applicationDevice);
    expect(restored.ino.toString()).toBe(binding.applicationInode);
    expect(existsSync(previous)).toBe(false);

    await expect(verifyReceiptPreviousApplicationBinding(binding, {
      serverReleaseRoot,
      restoredDirectoryApplicationPath: application,
    })).resolves.toBeUndefined();
    await expect(verifyReceiptPreviousApplicationBinding(binding, {
      serverReleaseRoot,
    })).rejects.toThrow();

    // Matching bytes are insufficient after the rollback commitment: replacing
    // the restored directory creates a new inode and must fail the immutable
    // receipt identity check rather than being accepted as a reconstruction.
    rmSync(application, { recursive: true });
    mkdirSync(application);
    writeFileSync(join(application, "old.txt"), "old\n");
    expect(await canonicalApplicationTreeFingerprint(application)).toBe(originalTreeSha256);
    const replacement = lstatSync(application, { bigint: true });
    expect(replacement.ino.toString()).not.toBe(binding.applicationInode);
    await expect(verifyReceiptPreviousApplicationBinding(binding, {
      serverReleaseRoot,
      restoredDirectoryApplicationPath: application,
    })).rejects.toThrow("dev/inode");
  });

  test("rollback refuses a stale receipt whose deployed server or static identity is not active", () => {
    const observed: ReleasePointerSnapshot = {
      application: {
        kind: "symlink",
        target: "/releases/deployed",
        device: "ignored",
        inode: "ignored",
      },
      staticReleaseId: "deployed",
      staticManifestSha256: "deployed-static-manifest",
    };
    const expected = {
      applicationTarget: "/releases/deployed",
      staticReleaseId: "deployed",
      staticManifestSha256: "deployed-static-manifest",
    };
    expect(() => assertRollbackActiveReleaseMatchesReceipt(observed, expected)).not.toThrow();
    expect(() => assertRollbackActiveReleaseMatchesReceipt({
      ...observed,
      application: { ...observed.application, target: "/releases/other" },
    }, expected)).toThrow("stale-receipt rollback is refused");
    expect(() => assertRollbackActiveReleaseMatchesReceipt({
      ...observed,
      staticManifestSha256: "other-static-manifest",
    }, expected)).toThrow("stale-receipt rollback is refused");
  });

  test("the maintenance gate counts only active Ti-Scale-controlled work and the state hash detects changes", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "gate.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const now = "2026-07-19T00:00:00.000Z";
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          scope_json, success_criteria_json, retention_policy_json,
          memory_policy_json, created_by, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', '{}', '[]', '{}', '{}', ?, ?, ?, 'ti_scale')
      `).run("mission_gate", "Gate", "Verify release gate", "test", now, now);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          created_at, updated_at, control_plane
        ) VALUES (?, ?, 'guided', 'running', '{}', '{}', ?, ?, 'ti_scale')
      `).run("run_gate", "mission_gate", now, now);
    } finally { database.close(); }

    const before = canonicalDatabaseFingerprint(databasePath);
    expect(queryActiveV2Work(databasePath).activeRuns).toEqual([{ id: "run_gate", status: "running" }]);
    const update = createDatabaseConnection({ filename: databasePath });
    try {
      update.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = 'mission_gate'").run();
      update.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = 'run_gate'").run();
    } finally { update.close(); }
    expect(queryActiveV2Work(databasePath).activeRuns).toEqual([]);
    expect(canonicalDatabaseFingerprint(databasePath)).not.toBe(before);
  });

  test("the maintenance gate fails closed for active import, confirmation, and continuation writers", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "durable-writer-gate.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    const now = "2026-07-19T00:00:00.000Z";
    const future = "2099-07-19T00:15:00.000Z";
    const expired = "2000-01-01T00:00:00.000Z";
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          scope_json, success_criteria_json, retention_policy_json,
          memory_policy_json, created_by, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'completed', 'verified', '{}', '[]', '{}', '{}', ?, ?, ?, 'ti_scale')
      `).run("mission_writer_gate", "Writer gate", "Verify durable writer gate", "test", now, now);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          created_at, updated_at, control_plane
        ) VALUES (?, ?, 'guided', 'completed', '{}', '{}', ?, ?, 'ti_scale')
      `).run("run_writer_gate", "mission_writer_gate", now, now);
      database.prepare(`
        INSERT INTO runtime_continuations (
          id, run_id, kind, source_id, payload_json, status, attempt_count,
          available_at, lease_owner, lease_expires_at, created_at, updated_at
        ) VALUES (?, ?, 'evaluation_pending', ?, '{}', 'processing', 1, ?, ?, ?, ?, ?)
      `).run(
        "continuation_writer_gate", "run_writer_gate", "terminal-run", now,
        "release-gate-worker", future, now, now,
      );
      database.prepare(`
        INSERT INTO runtime_continuations (
          id, run_id, kind, source_id, payload_json, status, attempt_count,
          available_at, created_at, updated_at
        ) VALUES (?, ?, 'evaluation_pending', ?, '{}', 'pending', 0, ?, ?, ?)
      `).run(
        "continuation_pending_writer_gate", "run_writer_gate", "future-terminal-run",
        future, now, now,
      );
      database.prepare(`
        INSERT INTO runtime_continuations (
          id, run_id, kind, source_id, payload_json, status, attempt_count,
          available_at, lease_owner, lease_expires_at, created_at, updated_at
        ) VALUES (?, ?, 'evaluation_pending', ?, '{}', 'processing', 1, ?, ?, ?, ?, ?)
      `).run(
        "continuation_expired_writer_gate", "run_writer_gate", "expired-terminal-run", now,
        "crashed-release-gate-worker", expired, now, now,
      );
      database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory, started_at
        ) VALUES (?, 'running', '[]', ?, ?, ?)
      `).run("migration_writer_gate", databasePath, workspace, now);
      database.prepare(`
        INSERT INTO legacy_migration_sources (
          id, migration_id, source_path, relative_path, source_type, source_identity,
          source_sha256, byte_size, modified_at, status, discovered_at
        ) VALUES (?, ?, ?, ?, 'fixture', ?, ?, 0, ?, 'importing', ?)
      `).run(
        "source_writer_gate", "migration_writer_gate", join(workspace, "source"),
        "source", "fixture-source", "a".repeat(64), now, now,
      );
      database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, updated_by, updated_at)
        VALUES (?, ?, 'private', 'test', ?)
      `).run(
        `historical_attack_knowledge.confirm_all.${"b".repeat(64)}`,
        JSON.stringify({
          status: "in_progress",
          lease: { owner: "confirmation-worker", expiresAt: future },
        }),
        now,
      );
    } finally { database.close(); }

    const active = queryActiveV2Work(databasePath);
    expect(active.activeRuns).toEqual([]);
    expect(active.activeDatabaseWriters).toEqual([
      {
        kind: "historical_confirmation",
        id: `historical_attack_knowledge.confirm_all.${"b".repeat(64)}`,
        status: "in_progress",
        leaseExpiresAt: future,
      },
      {
        kind: "legacy_migration_run",
        id: "migration_writer_gate",
        status: "running",
        leaseExpiresAt: null,
      },
      {
        kind: "legacy_migration_source",
        id: "source_writer_gate",
        status: "importing",
        leaseExpiresAt: null,
      },
      {
        kind: "runtime_continuation",
        id: "continuation_expired_writer_gate",
        status: "processing",
        leaseExpiresAt: expired,
      },
      {
        kind: "runtime_continuation",
        id: "continuation_pending_writer_gate",
        status: "pending",
        leaseExpiresAt: null,
      },
      {
        kind: "runtime_continuation",
        id: "continuation_writer_gate",
        status: "processing",
        leaseExpiresAt: future,
      },
    ]);
    expect(() => assertNoActiveWorkSnapshot(active)).toThrow(
      "legacy_migration_run:migration_writer_gate:running",
    );

    const completed = createDatabaseConnection({ filename: databasePath });
    try {
      completed.prepare(`
        UPDATE runtime_continuations SET status='completed', lease_owner=NULL,
          lease_expires_at=NULL, completed_at=? WHERE id IN (?, ?, ?)
      `).run(
        now,
        "continuation_writer_gate",
        "continuation_pending_writer_gate",
        "continuation_expired_writer_gate",
      );
      completed.prepare("UPDATE legacy_migration_sources SET status='completed', completed_at=? WHERE id=?")
        .run(now, "source_writer_gate");
      completed.prepare("UPDATE legacy_migration_runs SET status='completed', completed_at=? WHERE id=?")
        .run(now, "migration_writer_gate");
      completed.prepare(`
        UPDATE settings SET value_json = ?, updated_at = ?
        WHERE key = ?
      `).run(
        JSON.stringify({ status: "completed", lease: null }),
        now,
        `historical_attack_knowledge.confirm_all.${"b".repeat(64)}`,
      );
    } finally { completed.close(); }

    const quiesced = queryActiveV2Work(databasePath);
    expect(quiesced.activeDatabaseWriters).toEqual([]);
    expect(() => assertNoActiveWorkSnapshot(quiesced)).not.toThrow();
  });

  test("the maintenance gate blocks pending, expired, and actively leased hazard jobs before startup can mutate the source fingerprint", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "startup-drainable-hazard-gate.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    const now = "2026-07-22T00:00:00.000Z";
    const expired = "2000-01-01T00:00:00.000Z";
    const future = "2099-07-22T00:00:00.000Z";
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          scope_json, success_criteria_json, retention_policy_json,
          memory_policy_json, created_by, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'completed', 'verified', '{}', '[]', '{}', '{}', ?, ?, ?, 'ti_scale')
      `).run("mission_hazard_gate", "Hazard gate", "Prove startup-drainable admission", "test", now, now);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          created_at, updated_at, control_plane
        ) VALUES (?, ?, 'guided', 'completed', '{}', '{}', ?, ?, 'ti_scale')
      `).run("run_hazard_gate", "mission_hazard_gate", now, now);
      const insertEvent = database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at,
          actor_type, actor_id, summary, payload_json, schema_version,
          journey, sensitivity, redaction_json, created_at
        ) VALUES (?, ?, ?, ?, 'operational_hazard.reset_verified', ?,
          'operator', 'operator:test', 'Verified disposable-lab reset', '{}', 1,
          'guided', 'private', '{}', ?)
      `);
      insertEvent.run("event_hazard_pending", "mission_hazard_gate", "run_hazard_gate", 1, now, now);
      insertEvent.run("event_hazard_expired", "mission_hazard_gate", "run_hazard_gate", 2, now, now);
      insertEvent.run("event_hazard_active", "mission_hazard_gate", "run_hazard_gate", 3, now, now);

      database.prepare(`
        UPDATE operational_hazard_observation_jobs
        SET status = 'processing', lease_owner = 'crashed-worker',
          lease_expires_at = ?, claimed_at = ?, updated_at = ?
        WHERE event_id = ?
      `).run(expired, expired, expired, "event_hazard_expired");
      database.prepare(`
        UPDATE operational_hazard_observation_jobs
        SET status = 'processing', lease_owner = 'active-worker',
          lease_expires_at = ?, claimed_at = ?, updated_at = ?
        WHERE event_id = ?
      `).run(future, now, now, "event_hazard_active");

      const sourceFingerprint = canonicalReleaseDataFingerprint(databasePath);
      const active = queryActiveV2Work(databasePath);
      expect(active.activeDatabaseWriters).toEqual([
        {
          kind: "operational_hazard_observation_job",
          id: "event_hazard_active",
          status: "processing",
          leaseExpiresAt: future,
        },
        {
          kind: "operational_hazard_observation_job",
          id: "event_hazard_expired",
          status: "processing",
          leaseExpiresAt: expired,
        },
        {
          kind: "operational_hazard_observation_job",
          id: "event_hazard_pending",
          status: "pending",
          leaseExpiresAt: null,
        },
      ]);
      expect(() => assertNoActiveWorkSnapshot(active)).toThrow(
        "operational_hazard_observation_job:event_hazard_active:processing",
      );
      expect(canonicalReleaseDataFingerprint(databasePath)).toBe(sourceFingerprint);

      // This models the exact forbidden sequence: if recovery ignored these
      // jobs and started the service, startup would reclaim the expired lease
      // and drain it together with the due pending job before running-state
      // verification. The active lease remains visible and still blocks.
      const startupWorker = new OperationalHazardObservationWorker(database, {
        hmacKey: "release-startup-drain-regression-key-2026",
        clock: () => new Date(now),
        workerId: "release-startup-drain-regression",
      });
      startupWorker.start();
      startupWorker.stop();
      expect(canonicalReleaseDataFingerprint(databasePath)).not.toBe(sourceFingerprint);
      expect(queryActiveV2Work(databasePath).activeDatabaseWriters).toEqual([{
        kind: "operational_hazard_observation_job",
        id: "event_hazard_active",
        status: "processing",
        leaseExpiresAt: future,
      }]);

      database.prepare(`
        UPDATE operational_hazard_observation_jobs
        SET status = 'completed', lease_owner = NULL, lease_expires_at = NULL,
          completed_at = ?, updated_at = ?
        WHERE event_id = ?
      `).run(now, now, "event_hazard_active");
      const quiesced = queryActiveV2Work(databasePath);
      expect(quiesced.activeDatabaseWriters).toEqual([]);
      expect(() => assertNoActiveWorkSnapshot(quiesced)).not.toThrow();
    } finally { database.close(); }
  });

  test("the maintenance gate blocks every startup-drainable event outbox record", async () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "startup-drainable-outbox-gate.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    const now = "2026-07-22T00:00:00.000Z";
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          scope_json, success_criteria_json, retention_policy_json,
          memory_policy_json, created_by, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'completed', 'verified', '{}', '[]', '{}', '{}', ?, ?, ?, 'ti_scale')
      `).run("mission_outbox_gate", "Outbox gate", "Prove startup outbox admission", "test", now, now);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          created_at, updated_at, control_plane
        ) VALUES (?, ?, 'guided', 'completed', '{}', '{}', ?, ?, 'ti_scale')
      `).run("run_outbox_gate", "mission_outbox_gate", now, now);
      database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at,
          actor_type, actor_id, summary, payload_json, schema_version,
          journey, sensitivity, redaction_json, created_at
        ) VALUES (?, ?, ?, 1, 'fixture.completed', ?, 'system', 'test',
          'Fixture completion event', '{}', 1, 'guided', 'internal', '{}', ?)
      `).run("event_outbox_gate", "mission_outbox_gate", "run_outbox_gate", now, now);
      database.prepare(`
        INSERT INTO event_outbox (
          id, event_id, topic, payload_json, status, attempt_count,
          available_at, created_at
        ) VALUES (?, ?, 'events', '{}', 'pending', 0, ?, ?)
      `).run("outbox_gate", "event_outbox_gate", now, now);

      const before = canonicalReleaseDataFingerprint(databasePath);
      const active = queryActiveV2Work(databasePath);
      expect(active.activeDatabaseWriters).toContainEqual({
        kind: "event_outbox",
        id: "outbox_gate",
        status: "pending",
        leaseExpiresAt: null,
      });
      expect(() => assertNoActiveWorkSnapshot(active)).toThrow("event_outbox:outbox_gate:pending");

      const stream = new EventStreamService({
        repository: new EventRepository(database),
        clock: () => new Date(now),
        pollIntervalMs: 500,
      });
      stream.start();
      await stream.stop();
      expect(canonicalReleaseDataFingerprint(databasePath)).not.toBe(before);
      expect(queryActiveV2Work(databasePath).activeDatabaseWriters).toEqual([]);
    } finally { database.close(); }
  });

  test("surfaces an importing child of a terminal failed migration for reconciliation without treating it as a writer", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "terminal-failed-child.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    const startedAt = "2026-07-20T00:00:00.000Z";
    const completedAt = "2026-07-20T00:05:00.000Z";
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          error_summary, started_at, completed_at
        ) VALUES (?, 'failed', ?, ?, ?, ?, ?, ?)
      `).run(
        "migration_terminal_failed",
        JSON.stringify([join(workspace, "source")]),
        databasePath,
        join(workspace, "output"),
        "import process terminated and requires audited reconciliation",
        startedAt,
        completedAt,
      );
      database.prepare(`
        INSERT INTO legacy_migration_sources (
          id, migration_id, source_path, relative_path, source_type,
          source_identity, source_sha256, byte_size, modified_at, status, discovered_at
        ) VALUES (?, ?, ?, ?, 'fixture', ?, ?, 0, ?, 'importing', ?)
      `).run(
        "source_terminal_failed",
        "migration_terminal_failed",
        join(workspace, "source"),
        "source",
        "terminal-failed-source",
        "c".repeat(64),
        startedAt,
        startedAt,
      );
    } finally {
      database.close();
    }

    const classified = queryActiveV2Work(databasePath);
    expect(classified.activeDatabaseWriters).toEqual([]);
    expect(classified.reconciliationRequired).toEqual([{
      kind: "legacy_migration_source",
      id: "source_terminal_failed",
      status: "reconciliation_required",
      sourceStatus: "importing",
      parentMigrationId: "migration_terminal_failed",
      parentStatus: "failed",
    }]);
    expect(() => assertNoActiveWorkSnapshot(classified)).not.toThrow();

    // A merely labelled "failed" parent without terminal timestamp/error
    // proof remains fail-closed as active durable work.
    const incomplete = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      incomplete.prepare(`
        UPDATE legacy_migration_runs SET completed_at = NULL, error_summary = NULL WHERE id = ?
      `).run("migration_terminal_failed");
    } finally {
      incomplete.close();
    }
    const refused = queryActiveV2Work(databasePath);
    expect(refused.reconciliationRequired).toEqual([]);
    expect(refused.activeDatabaseWriters).toEqual([{
      kind: "legacy_migration_source",
      id: "source_terminal_failed",
      status: "importing",
      leaseExpiresAt: null,
    }]);
    expect(() => assertNoActiveWorkSnapshot(refused)).toThrow(
      "legacy_migration_source:source_terminal_failed:importing",
    );
  });

  test("the maintenance snapshot exposes registered canonical writer leases", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "canonical-writer-gate.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const leases = new CanonicalDatabaseLeaseService(database);
      const writer = leases.acquireWriter({
        ownerId: "operator:test",
        operation: "obsidian-export",
      });
      const active = queryActiveV2Work(databasePath);
      expect(active.activeDatabaseWriters).toEqual([{
        kind: "canonical_database_writer",
        id: writer.id,
        status: "obsidian-export",
        leaseExpiresAt: writer.expiresAt,
      }]);
      expect(() => assertNoActiveWorkSnapshot(active)).toThrow(
        `canonical_database_writer:${writer.id}:obsidian-export`,
      );
      leases.release(writer);
      expect(queryActiveV2Work(databasePath).activeDatabaseWriters).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("the bounded fingerprint is byte-compatible with v4 row-set ordering and preserves duplicates", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "bounded-fingerprint.sqlite");
    const database = createDatabaseConnection({ filename: databasePath, verifyIntegrity: false });
    try {
      database.exec(`
        CREATE TABLE mixed_rows (
          label TEXT,
          count INTEGER,
          ratio REAL,
          payload BLOB,
          optional TEXT
        );
        CREATE INDEX mixed_rows_label ON mixed_rows(label);
        CREATE TABLE stable_keys (
          namespace TEXT NOT NULL,
          key TEXT NOT NULL,
          value TEXT NOT NULL,
          PRIMARY KEY (namespace, key)
        ) WITHOUT ROWID;
        CREATE VIEW mixed_labels AS SELECT label FROM mixed_rows;
      `);
      const insert = database.prepare(`
        INSERT INTO mixed_rows (label, count, ratio, payload, optional)
        VALUES (?, ?, ?, ?, ?)
      `);
      insert.run("zeta", 9_007_199_254_740_000n, 1.25, Buffer.from([0, 1, 2, 255]), null);
      insert.run("alpha-λ", -42, -0.5, Buffer.from("titanium"), "present");
      insert.run("duplicate", 7, 3.5, Buffer.from([7]), null);
      insert.run("duplicate", 7, 3.5, Buffer.from([7]), null);
      database.prepare(`
        INSERT INTO stable_keys (namespace, key, value) VALUES (?, ?, ?)
      `).run("attack", "vector", "version-bound");
    } finally {
      database.close();
    }

    const reference = legacyReferenceDatabaseFingerprint(databasePath);
    const bounded = canonicalDatabaseFingerprint(databasePath);
    expect(bounded).toBe(reference);

    const update = createDatabaseConnection({ filename: databasePath, verifyIntegrity: false });
    try {
      update.prepare(`DELETE FROM mixed_rows WHERE rowid = (
        SELECT MAX(rowid) FROM mixed_rows WHERE label = 'duplicate'
      )`).run();
    } finally {
      update.close();
    }
    expect(canonicalDatabaseFingerprint(databasePath)).not.toBe(bounded);
  });

  test("v4 rollback fingerprint excludes only runtime projection, telemetry, lease, and fence tables", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "rollback-fingerprint.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const stableBefore = canonicalReleaseDataFingerprint(databasePath);
      expect(RELEASE_DATA_FINGERPRINT_POLICY).toBe(
        "release_data_excluding_runtime_projection_telemetry_lease_fence_and_classified_startup_readiness_rows_v4",
      );
      expect(RELEASE_DATA_FINGERPRINT_ROW_EXCLUDED_TABLES).toEqual([
        "canonical_database_lease_fence",
        "canonical_database_leases",
        "agents",
        "agent_capabilities",
        "health_snapshots",
        "mcp_servers",
      ]);
      expect(RELEASE_DATA_FINGERPRINT_ROW_CLASS_EXCLUSIONS).toEqual({
        provider_turns: "startup_readiness",
        memory_context_packs: "startup_readiness",
        provider_exposure_receipts: "startup_readiness",
      });
      expect(() => assertExactReleaseDataFingerprintPolicy(RELEASE_DATA_FINGERPRINT_POLICY)).not.toThrow();
      expect(() => assertExactReleaseDataFingerprintPolicy("release_data_excluding_lease_rows_v1"))
        .toThrow("not silently reinterpreted");
      expect(() => assertExactReleaseDataFingerprintPolicy("release_data_excluding_lease_and_fence_rows_v2"))
        .toThrow("not silently reinterpreted");
      expect(() => assertExactReleaseDataFingerprintPolicy(
        "release_data_excluding_runtime_projection_telemetry_lease_and_fence_rows_v3",
      )).toThrow("not silently reinterpreted");

      const fullBefore = canonicalDatabaseFingerprint(databasePath);
      const now = "2026-07-21T00:00:00.000Z";
      database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json,
          tool_policy_json, configuration_json, version,
          last_heartbeat_at, created_at, updated_at
        ) VALUES (?, ?, ?, 'available', '{}', '{}', '{}', 'runtime-v1', ?, ?, ?)
      `).run("runtime-agent", "recon", "Runtime Recon", now, now, now);
      database.prepare(`
        INSERT INTO agent_capabilities (agent_id, capability, source, enabled, metadata_json)
        VALUES (?, ?, 'live-route-attestation', 1, '{}')
      `).run("runtime-agent", "network.recon");
      database.prepare(`
        INSERT INTO mcp_servers (
          id, name, transport, endpoint_redacted, status,
          capabilities_json, policy_json, last_checked_at, created_at, updated_at
        ) VALUES (?, ?, 'stdio', 'local://runtime', 'healthy', '["scan"]', '{}', ?, ?, ?)
      `).run("runtime-mcp", "Runtime MCP", now, now, now);
      database.prepare(`
        INSERT INTO health_snapshots (
          id, component_type, component_id, status, metrics_json, message, captured_at
        ) VALUES (?, 'provider', 'runtime-provider', 'healthy', '{}', 'Runtime projection', ?)
      `).run("runtime-health", now);
      const leases = new CanonicalDatabaseLeaseService(database);
      const writer = leases.acquireWriter({
        ownerId: "release-fingerprint-test",
        operation: "standalone-service-runtime",
      });
      const renewed = leases.renew(writer);
      leases.release(renewed, "graceful_shutdown");
      expect(canonicalDatabaseFingerprint(databasePath)).not.toBe(fullBefore);
      expect(canonicalReleaseDataFingerprint(databasePath)).toBe(stableBefore);
    } finally { database.close(); }
  });

  test("v4 rollback fingerprint still hashes excluded-table schemas and classification triggers", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "rollback-fingerprint-schema.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const before = canonicalReleaseDataFingerprint(databasePath);
      database.exec("ALTER TABLE health_snapshots ADD COLUMN release_schema_probe TEXT");
      expect(canonicalReleaseDataFingerprint(databasePath)).not.toBe(before);

      const beforeTriggerRemoval = canonicalReleaseDataFingerprint(databasePath);
      database.exec("DROP TRIGGER startup_readiness_context_pack_insert_guard");
      expect(canonicalReleaseDataFingerprint(databasePath)).not.toBe(beforeTriggerRemoval);
    } finally { database.close(); }
  });

  test("v4 rollback fingerprint excludes only classified readiness lineage rows", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "rollback-fingerprint-readiness.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const releaseBefore = canonicalReleaseDataFingerprint(databasePath);
      const completeBefore = canonicalDatabaseFingerprint(databasePath);
      const now = "2026-07-22T00:00:00.000Z";
      database.prepare(`
        INSERT INTO provider_turns (
          id, provider, model, status, started_at, release_data_class
        ) VALUES ('provider-readiness-fingerprint', 'openrouter', 'openai/gpt-5.2',
          'started', ?, 'startup_readiness')
      `).run(now);
      database.prepare(`
        INSERT INTO memory_context_packs (
          id, journey, purpose, query_redacted, scope_policy_json, context_budget,
          retrieval_metrics_json, created_by, created_at, release_data_class
        ) VALUES (
          'pack-readiness-fingerprint', 'guided',
          'Content-free public-provider readiness audit',
          'content-free readiness acknowledgement',
          '{"allowGlobal":false,"allowedStatuses":["confirmed","verified"],"contextBudget":0,"exactNodeIds":[],"exactNodeIdsOnly":true,"graphDepth":0,"journey":"guided","maximumSensitivity":"public"}',
          0, '{"retrievedCount":0,"source":"openrouter-content-free-readiness"}',
          'openrouter-readiness-monitor', ?, 'startup_readiness'
        )
      `).run(now);
      database.prepare(`
        INSERT INTO provider_exposure_receipts (
          id, provider_id, model_id, provider_turn_id, context_pack_id,
          disclosure_policy_version, input_classification,
          selected_context_ids_json, rejected_context_ids_json,
          sanitization_actions_json, untrusted_content_envelope_hash,
          exposed_payload_hash, blocked, created_at, release_data_class
        ) VALUES (
          'receipt-readiness-fingerprint', 'openrouter', 'openai/gpt-5.2',
          'provider-readiness-fingerprint', 'pack-readiness-fingerprint',
          'brain-provider-context-v1', 'public', '[]', '[]', '[]', ?, ?, 0, ?,
          'startup_readiness'
        )
      `).run("a".repeat(64), "a".repeat(64), now);

      expect(canonicalDatabaseFingerprint(databasePath)).not.toBe(completeBefore);
      expect(canonicalReleaseDataFingerprint(databasePath)).toBe(releaseBefore);
      database.prepare(`
        UPDATE provider_turns SET status = 'completed', ended_at = ?
        WHERE id = 'provider-readiness-fingerprint'
      `).run(now);
      expect(canonicalReleaseDataFingerprint(databasePath)).toBe(releaseBefore);

      database.prepare(`
        INSERT INTO provider_turns (id, provider, status, started_at)
        VALUES ('canonical-provider-turn', 'openrouter', 'started', ?)
      `).run(now);
      const afterCanonicalTurn = canonicalReleaseDataFingerprint(databasePath);
      expect(afterCanonicalTurn).not.toBe(releaseBefore);
      database.prepare(`
        INSERT INTO memory_context_packs (
          id, journey, purpose, scope_policy_json, context_budget,
          retrieval_metrics_json, created_by, created_at
        ) VALUES (
          'canonical-context-pack', 'guided', 'Operational provider context',
          '{"allowGlobal":false,"contextBudget":0,"journey":"guided","maximumSensitivity":"public"}',
          0, '{}', 'guided-runtime', ?
        )
      `).run(now);
      const afterCanonicalPack = canonicalReleaseDataFingerprint(databasePath);
      expect(afterCanonicalPack).not.toBe(afterCanonicalTurn);
      database.prepare(`
        INSERT INTO provider_exposure_receipts (
          id, provider_id, model_id, provider_turn_id, context_pack_id,
          disclosure_policy_version, input_classification,
          selected_context_ids_json, rejected_context_ids_json,
          sanitization_actions_json, exposed_payload_hash, blocked, created_at
        ) VALUES (
          'canonical-exposure-receipt', 'openrouter', 'openai/gpt-5.2',
          'canonical-provider-turn', 'canonical-context-pack',
          'brain-provider-context-v1', 'public', '[]', '[]', '[]', ?, 0, ?
        )
      `).run("b".repeat(64), now);
      expect(canonicalReleaseDataFingerprint(databasePath)).not.toBe(afterCanonicalPack);
    } finally { database.close(); }
  });

  test("v4 fingerprints every provider and memory audit row on a pre-v38 source database", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "rollback-fingerprint-pre-v38.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 37));
      expect(database.prepare(`
        SELECT MAX(version) AS version FROM schema_migrations
      `).get()).toEqual({ version: 37 });
      const before = canonicalReleaseDataFingerprint(databasePath);
      database.prepare(`
        INSERT INTO provider_turns (id, provider, status, started_at)
        VALUES ('pre-v38-provider-turn', 'openrouter', 'started', ?)
      `).run("2026-07-22T00:00:00.000Z");
      expect(canonicalReleaseDataFingerprint(databasePath)).not.toBe(before);
    } finally { database.close(); }
  });

  test("v4 rollback fingerprint detects mission, operator-preference, and evidence drift", () => {
    const { workspace } = fixture();
    const databasePath = join(workspace, "rollback-fingerprint-durable-data.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const now = "2026-07-21T00:00:00.000Z";
      const beforeMission = canonicalReleaseDataFingerprint(databasePath);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          scope_json, success_criteria_json, retention_policy_json,
          memory_policy_json, created_by, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'draft', 'verified', '{}', '[]', '{}', '{}', ?, ?, ?, 'ti_scale')
      `).run("mission_fingerprint_drift", "Drift", "Detect real data drift", "test", now, now);
      const afterMission = canonicalReleaseDataFingerprint(databasePath);
      expect(afterMission).not.toBe(beforeMission);

      database.prepare(`
        INSERT INTO preference_profiles (
          id, operator_id, scope, preference_key, value_json,
          confirmation_state, confidence, consent_policy, version,
          confirmed_at, created_at, updated_at
        ) VALUES (?, ?, 'global', 'explanation_depth', '"technical-readable"',
          'confirmed', 1, 'explicit_confirmation', 1, ?, ?, ?)
      `).run("preference_fingerprint_drift", "operator", now, now, now);
      const afterPreference = canonicalReleaseDataFingerprint(databasePath);
      expect(afterPreference).not.toBe(afterMission);

      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES (?, ?, 'test', ?, 'authorized-target', 'artifact', ?, '{}',
          1, 'internal', 'verified', 'Durable evidence', 'test', ?)
      `).run(
        "evidence_fingerprint_drift",
        "mission_fingerprint_drift",
        now,
        "a".repeat(64),
        now,
      );
      expect(canonicalReleaseDataFingerprint(databasePath)).not.toBe(afterPreference);
    } finally { database.close(); }
  });
});

describe("stage-aware automatic recovery", () => {
  const stopSnapshot = (
    values: Partial<ServiceStopSnapshot> = {},
  ): ServiceStopSnapshot => ({
    activeState: "inactive",
    mainPid: 0,
    controlGroup: "/system.slice/ti-scale.service",
    controlGroupProcessIds: [],
    portListening: false,
    ...values,
  });

  function operations(log: string[]) {
    return {
      stop: () => { log.push("stop"); },
      restoreStatic: () => { log.push("static"); },
      restoreApplication: () => { log.push("application"); },
      restoreDatabase: () => { log.push("database"); },
      restoreVault: () => { log.push("vault"); },
      verifyVaultConsistency: () => { log.push("vault-consistency"); },
      start: () => { log.push("start"); },
      verify: () => { log.push("verify"); },
    };
  }

  test("a pre-checksum or pre-migration failure restarts the old service without restoring the database", async () => {
    const beforeStop: string[] = [];
    await recoverFailedRelease({
      serviceStopped: false,
      staticActivated: false,
      applicationSwapped: false,
      databaseMayBeChanged: false,
      vaultMayBeChanged: false,
    }, operations(beforeStop));
    expect(beforeStop).toEqual(["stop", "start", "verify"]);

    const afterStop: string[] = [];
    await recoverFailedRelease({
      serviceStopped: true,
      staticActivated: false,
      applicationSwapped: false,
      databaseMayBeChanged: false,
      vaultMayBeChanged: false,
    }, operations(afterStop));
    expect(afterStop).toEqual(["start", "verify"]);
  });

  test("a migration/startup failure restores static, server, database, and Vault before restart", async () => {
    const log: string[] = [];
    await recoverFailedRelease({
      serviceStopped: true,
      staticActivated: true,
      applicationSwapped: true,
      databaseMayBeChanged: true,
      vaultMayBeChanged: true,
    }, operations(log));
    expect(log).toEqual([
      "static", "application", "database", "vault", "vault-consistency", "start", "verify",
    ]);
  });

  test("candidate Vault writes alone are restored and checked before the previous release restarts", async () => {
    const log: string[] = [];
    await recoverFailedRelease({
      serviceStopped: true,
      staticActivated: false,
      applicationSwapped: false,
      databaseMayBeChanged: false,
      vaultMayBeChanged: true,
    }, operations(log));
    expect(log).toEqual(["vault", "vault-consistency", "start", "verify"]);
  });

  test("failed/MainPID=0 is recovery-only and restarts the unchanged release without retrying stop", async () => {
    const deploymentFailure = new Error("systemctl stop timed out");
    const calls: string[] = [];
    const durableState = {
      applicationPointer: "/opt/ti-scale-old",
      staticPointer: "static-old",
      databaseFingerprint: "database-old",
    };
    const before = { ...durableState };

    expect(serviceCanRestartUnchanged(stopSnapshot({ activeState: "failed" }))).toBe(true);
    expect(serviceCanRestartUnchanged(stopSnapshot())).toBe(true);
    expect(serviceCanRestartUnchanged(stopSnapshot({ activeState: "failed", mainPid: 9001 }))).toBe(false);
    expect(serviceCanRestartUnchanged(stopSnapshot({ activeState: "deactivating" }))).toBe(false);
    expect(serviceCanRestartUnchanged(stopSnapshot({
      activeState: "failed",
      controlGroupProcessIds: [9002],
    }))).toBe(false);
    expect(serviceCanRestartUnchanged(stopSnapshot({ activeState: "failed", portListening: true }))).toBe(false);

    const releaseAttempt = async (): Promise<void> => {
      await executePreparedDeploymentBoundary({
        stopAndProveClean: () => {
          calls.push("stop-timeout");
          throw deploymentFailure;
        },
        applyAndVerify: () => { calls.push("unexpected-apply"); },
        recoverAndVerifyPrevious: async () => {
          await restartUnchangedServiceAfterFailedStop({
            inspect: () => {
              calls.push("inspect:failed:0");
              return stopSnapshot({ activeState: "failed" });
            },
            stop: () => { calls.push("unexpected-stop"); },
            beforeStart: () => {
              calls.push("prove-unchanged");
              expect(durableState).toEqual(before);
            },
            start: () => { calls.push("start-old-release"); },
            verify: () => {
              calls.push("verify-old-release");
              expect(durableState).toEqual(before);
            },
          });
        },
      });
    };

    // Recovery restores availability; it does not convert a failed deploy
    // into success or authorize any pointer/database mutation.
    await expect(releaseAttempt()).rejects.toBe(deploymentFailure);
    expect(calls).toEqual([
      "stop-timeout",
      "inspect:failed:0",
      "prove-unchanged",
      "start-old-release",
      "verify-old-release",
    ]);
    expect(durableState).toEqual(before);
  });

  const failedStopIdentity = (
    overrides: Partial<ServiceStopReleaseIdentity> = {},
  ): ServiceStopReleaseIdentity => ({
    pointers: {
      application: {
        kind: "symlink",
        target: "/opt/ti-scale-server-releases/releases/source",
        device: "2049",
        inode: "4097",
      },
      staticReleaseId: "static-source",
      staticManifestSha256: "a".repeat(64),
    },
    databaseSchema: 37,
    ...overrides,
  });

  test("normalizes a failed-but-empty unit only after complete release identity and quiescence proofs", () => {
    const calls: string[] = [];
    const snapshots = [
      stopSnapshot({ activeState: "failed" }),
      stopSnapshot(),
    ];
    const result = stopServiceWithGuardedFailedUnitNormalization({
      captureIdentity: () => {
        calls.push("identity");
        return failedStopIdentity();
      },
      stop: () => {
        calls.push("stop");
        throw new Error("database is locked");
      },
      inspect: () => {
        calls.push("inspect");
        return snapshots.shift()!;
      },
      assertNoActiveWork: () => { calls.push("work-clear"); },
      assertNoCanonicalDatabaseUsers: () => { calls.push("handles-clear"); },
      resetFailed: () => { calls.push("reset-failed"); },
      now: () => "2026-07-22T10:30:00.000Z",
    });

    expect(result.disposition).toBe("failed_unit_normalized");
    expect(result.snapshot.activeState).toBe("inactive");
    expect(result.compatibilityEvidence).toMatchObject({
      schemaVersion: "ti-scale.failed-service-stop-normalization.v1",
      recordedAt: "2026-07-22T10:30:00.000Z",
      stopCommandFailed: true,
      stopCommandFailure: { name: "Error", message: "database is locked" },
      proofs: {
        mainPidAbsent: true,
        controlGroupEmpty: true,
        port3132NotListening: true,
        canonicalDatabaseHandlesAbsent: true,
        activeRuntimeWorkAbsent: true,
        applicationPointerUnchanged: true,
        staticPointerUnchanged: true,
        databaseSchemaUnchanged: true,
      },
    });
    expect(calls).toEqual([
      "identity",
      "stop",
      "inspect",
      "work-clear",
      "identity",
      "handles-clear",
      "reset-failed",
      "inspect",
      "work-clear",
      "identity",
      "handles-clear",
    ]);
  });

  test("brackets stopped-service lease reconciliation with durable-work and OS-handle proofs", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-release-service-lease-boundary-"));
    roots.push(root);
    const databasePath = join(root, "canonical.sqlite");
    const setup = createDatabaseConnection({ filename: databasePath });
    migrateDatabase(setup);
    const now = new Date("2026-07-22T14:30:00.000Z");
    const leases = new CanonicalDatabaseLeaseService(setup, { clock: () => now });
    const serviceLease = leases.acquireWriter({
      ownerId: "ti-scale-service:4242",
      operation: "standalone-service-runtime",
      ttlMs: 60_000,
    });
    setup.close();
    const calls: string[] = [];
    const result = reconcileStoppedServiceRuntimeLeaseAtBoundary({
      databasePath,
      actorId: "release-controller:9000",
      boundaryId: "functional-release:release-a:service-stop",
      preStop: stopSnapshot({
        activeState: "active",
        mainPid: 4100,
        controlGroup: "/system.slice/ti-scale.service",
        controlGroupProcessIds: [4100, 4242],
        portListening: true,
      }),
      stopped: stopSnapshot({
        controlGroup: "/system.slice/ti-scale.service",
      }),
      assertNoActiveWork: () => { calls.push("work-clear"); },
      assertNoCanonicalDatabaseUsers: () => { calls.push("handles-clear"); },
      clock: () => now,
      createId: () => "audit_release_service_boundary",
      processExists: () => false,
    });
    expect(result).toMatchObject({
      status: "released",
      leaseId: serviceLease.id,
      ownerPid: 4242,
      releaseReason: "stopped_service_owner_absent",
    });
    expect(calls).toEqual(["work-clear", "handles-clear", "handles-clear"]);
    const verification = createDatabaseConnection({
      filename: databasePath,
      readonly: true,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      expect(verification.prepare(`
        SELECT released_at, release_reason FROM canonical_database_leases WHERE id = ?
      `).get(serviceLease.id)).toEqual({
        released_at: now.toISOString(),
        release_reason: "stopped_service_owner_absent",
      });
      expect(verification.prepare(`
        SELECT action FROM audit_records WHERE id = 'audit_release_service_boundary'
      `).get()).toEqual({
        action: "canonical_database_lease.stopped_service_owner_reconciled",
      });
    } finally {
      verification.close();
    }
  });

  test("does not reinterpret an ordinary successful inactive stop", () => {
    let resetCalls = 0;
    const result = stopServiceWithGuardedFailedUnitNormalization({
      captureIdentity: failedStopIdentity,
      stop: () => undefined,
      inspect: () => stopSnapshot(),
      assertNoActiveWork: () => { throw new Error("unreachable work proof"); },
      assertNoCanonicalDatabaseUsers: () => { throw new Error("unreachable handle proof"); },
      resetFailed: () => { resetCalls += 1; },
    });
    expect(result).toEqual({ disposition: "stopped", snapshot: stopSnapshot() });
    expect(resetCalls).toBe(0);
  });

  test("refuses every nonempty or nonfailed service state before reset-failed", () => {
    const unsafeSnapshots: readonly [string, ServiceStopSnapshot][] = [
      ["active state", stopSnapshot({ activeState: "active", mainPid: 7001 })],
      ["main process", stopSnapshot({ activeState: "failed", mainPid: 7001 })],
      ["cgroup process", stopSnapshot({ activeState: "failed", controlGroupProcessIds: [7002] })],
      ["port listener", stopSnapshot({ activeState: "failed", portListening: true })],
      ["transitional state", stopSnapshot({ activeState: "deactivating" })],
    ];
    for (const [label, snapshot] of unsafeSnapshots) {
      let resetCalls = 0;
      expect(() => stopServiceWithGuardedFailedUnitNormalization({
        captureIdentity: failedStopIdentity,
        stop: () => undefined,
        inspect: () => snapshot,
        assertNoActiveWork: () => undefined,
        assertNoCanonicalDatabaseUsers: () => undefined,
        resetFailed: () => { resetCalls += 1; },
      })).toThrow("eligible failed-but-empty unit");
      expect(`${label}:${String(resetCalls)}`).toBe(`${label}:0`);
    }
  });

  test("refuses reset-failed when durable work or canonical database handles remain", () => {
    for (const proof of ["work", "handles"] as const) {
      let resetCalls = 0;
      expect(() => stopServiceWithGuardedFailedUnitNormalization({
        captureIdentity: failedStopIdentity,
        stop: () => undefined,
        inspect: () => stopSnapshot({ activeState: "failed" }),
        assertNoActiveWork: () => {
          if (proof === "work") throw new Error("active durable work");
        },
        assertNoCanonicalDatabaseUsers: () => {
          if (proof === "handles") throw new Error("open canonical database handle");
        },
        resetFailed: () => { resetCalls += 1; },
      })).toThrow(proof === "work" ? "active durable work" : "open canonical database handle");
      expect(resetCalls).toBe(0);
    }
  });

  test("refuses reset-failed for application, static, manifest, or schema identity drift", () => {
    const source = failedStopIdentity();
    const drifts: readonly [string, ServiceStopReleaseIdentity][] = [
      ["application pointer", failedStopIdentity({
        pointers: {
          ...source.pointers,
          application: { ...source.pointers.application, target: `${source.pointers.application.target}-drift` },
        },
      })],
      ["static release pointer", failedStopIdentity({
        pointers: { ...source.pointers, staticReleaseId: "static-drift" },
      })],
      ["static release pointer", failedStopIdentity({
        pointers: { ...source.pointers, staticManifestSha256: "b".repeat(64) },
      })],
      ["database schema", failedStopIdentity({ databaseSchema: 38 })],
    ];
    for (const [error, drift] of drifts) {
      let identityCalls = 0;
      let resetCalls = 0;
      expect(() => stopServiceWithGuardedFailedUnitNormalization({
        captureIdentity: () => identityCalls++ === 0 ? source : drift,
        stop: () => undefined,
        inspect: () => stopSnapshot({ activeState: "failed" }),
        assertNoActiveWork: () => undefined,
        assertNoCanonicalDatabaseUsers: () => undefined,
        resetFailed: () => { resetCalls += 1; },
      })).toThrow(error);
      expect(resetCalls).toBe(0);
    }
  });

  test("rechecks all stop invariants after reset-failed and fails closed on a race", () => {
    const unsafeNormalizedSnapshots: readonly ServiceStopSnapshot[] = [
      stopSnapshot({ activeState: "failed" }),
      stopSnapshot({ mainPid: 7001 }),
      stopSnapshot({ controlGroupProcessIds: [7002] }),
      stopSnapshot({ portListening: true }),
    ];
    for (const unsafe of unsafeNormalizedSnapshots) {
      let inspectCalls = 0;
      let resetCalls = 0;
      expect(() => stopServiceWithGuardedFailedUnitNormalization({
        captureIdentity: failedStopIdentity,
        stop: () => undefined,
        inspect: () => inspectCalls++ === 0
          ? stopSnapshot({ activeState: "failed" })
          : unsafe,
        assertNoActiveWork: () => undefined,
        assertNoCanonicalDatabaseUsers: () => undefined,
        resetFailed: () => { resetCalls += 1; },
      })).toThrow("fully inactive unit");
      expect(resetCalls).toBe(1);
    }

    for (const proof of ["work", "handles", "identity"] as const) {
      let inspectCalls = 0;
      let workCalls = 0;
      let handleCalls = 0;
      let identityCalls = 0;
      const source = failedStopIdentity();
      expect(() => stopServiceWithGuardedFailedUnitNormalization({
        captureIdentity: () => {
          identityCalls += 1;
          if (proof === "identity" && identityCalls === 3) {
            return failedStopIdentity({ databaseSchema: 38 });
          }
          return source;
        },
        stop: () => undefined,
        inspect: () => inspectCalls++ === 0
          ? stopSnapshot({ activeState: "failed" })
          : stopSnapshot(),
        assertNoActiveWork: () => {
          workCalls += 1;
          if (proof === "work" && workCalls === 2) throw new Error("work appeared after reset");
        },
        assertNoCanonicalDatabaseUsers: () => {
          handleCalls += 1;
          if (proof === "handles" && handleCalls === 2) throw new Error("handle appeared after reset");
        },
        resetFailed: () => undefined,
      })).toThrow(
        proof === "work"
          ? "work appeared after reset"
          : proof === "handles"
            ? "handle appeared after reset"
            : "database schema changed after",
      );
    }
  });

  test("does not broaden a failed stop into inactive-unit or reset-command success", () => {
    let resetCalls = 0;
    expect(() => stopServiceWithGuardedFailedUnitNormalization({
      captureIdentity: failedStopIdentity,
      stop: () => { throw new Error("stop client error"); },
      inspect: () => stopSnapshot(),
      assertNoActiveWork: () => undefined,
      assertNoCanonicalDatabaseUsers: () => undefined,
      resetFailed: () => { resetCalls += 1; },
    })).toThrow("without a failed unit eligible");
    expect(resetCalls).toBe(0);

    expect(() => stopServiceWithGuardedFailedUnitNormalization({
      captureIdentity: failedStopIdentity,
      stop: () => undefined,
      inspect: () => stopSnapshot({ activeState: "failed" }),
      assertNoActiveWork: () => undefined,
      assertNoCanonicalDatabaseUsers: () => undefined,
      resetFailed: () => { throw new Error("reset failed"); },
    })).toThrow("reset failed");
  });

  test("unchanged-service recovery remains fail-closed while a process is still present", async () => {
    const calls: string[] = [];
    await expect(restartUnchangedServiceAfterFailedStop({
      inspect: () => {
        calls.push("inspect");
        return stopSnapshot({ activeState: "failed", mainPid: 4242 });
      },
      stop: () => {
        calls.push("stop-retry");
        throw new Error("stop retry timed out");
      },
      start: () => { calls.push("unexpected-start"); },
      verify: () => { calls.push("unexpected-verify"); },
    })).rejects.toThrow("process absence could not be proven");
    expect(calls).toEqual(["inspect", "stop-retry", "inspect"]);
  });

  test("guarded source commitment retries one dead wrapper and remains an exact-state outcome", async () => {
    let active = false;
    let starts = 0;
    let verifications = 0;
    const result = await ensureGuardedSourceRuntimeCommit({
      label: "Test source commitment",
      inspect: () => active
        ? stopSnapshot({
            activeState: "active",
            mainPid: 4242,
            controlGroupProcessIds: [4242],
            portListening: true,
          })
        : stopSnapshot(),
      start: () => {
        starts += 1;
        active = true;
      },
      waitAndVerify: () => {
        verifications += 1;
        if (verifications === 1) {
          active = false;
          throw new Error("guarded wrapper exited before readiness");
        }
      },
    });
    expect(result).toBe("already_exact");
    expect(starts).toBe(2);
    expect(verifications).toBe(2);
  });

  test("guarded observation can prove success after a systemctl client-side start error", async () => {
    let active = false;
    const calls: string[] = [];
    await expect(ensureGuardedSourceRuntimeCommit({
      label: "Ambiguous start source commitment",
      inspect: () => active
        ? stopSnapshot({
            activeState: "active",
            mainPid: 4343,
            controlGroupProcessIds: [4343],
            portListening: true,
          })
        : stopSnapshot(),
      start: () => {
        calls.push("start-reported-error");
        active = true;
        throw new Error("systemctl client timed out");
      },
      waitAndVerify: () => { calls.push("guarded-ready"); },
    })).resolves.toBe("already_exact");
    expect(calls).toEqual(["start-reported-error", "guarded-ready"]);
  });

  test("rollback initial-stop failure recovers only the unchanged current release", async () => {
    const primary = new Error("rollback systemctl stop timed out");
    const calls: string[] = [];
    let stopAttempted = false;
    let mutationStarted = false;
    const attempt = executePreparedDeploymentBoundary({
      stopAndProveClean: () => {
        calls.push("rollback-stop");
        stopAttempted = true;
        throw primary;
      },
      applyAndVerify: () => {
        mutationStarted = true;
        calls.push("unexpected-rollback-mutation");
      },
      recoverAndVerifyPrevious: () => recoverFailedRollback({
        stopAttempted,
        mutationStarted,
      }, {
        recoverUnchangedRelease: () => { calls.push("recover-unchanged-current-release"); },
        stopMutatedRelease: () => { calls.push("unexpected-stop-mutated-release"); },
        restoreCurrentRelease: () => { calls.push("unexpected-restore-current-release"); },
        startCurrentRelease: () => { calls.push("unexpected-start-current-release"); },
        verifyCurrentRelease: () => { calls.push("unexpected-verify-current-release"); },
      }),
    });

    await expect(attempt).rejects.toBe(primary);
    expect(calls).toEqual(["rollback-stop", "recover-unchanged-current-release"]);
    expect(mutationStarted).toBe(false);
  });

  test("rollback post-mutation failure restores preserved current pointers, database, and Vault before restart", async () => {
    const primary = new Error("rollback target startup failed");
    const calls: string[] = [];
    const preserved = {
      application: "current-release",
      static: "current-static",
      database: "current-database",
      vault: "current-vault",
    };
    const durable = { ...preserved };
    let stopAttempted = false;
    let mutationStarted = false;
    const attempt = executePreparedDeploymentBoundary({
      stopAndProveClean: () => {
        stopAttempted = true;
        calls.push("rollback-stop-clean");
      },
      applyAndVerify: () => {
        mutationStarted = true;
        durable.application = "previous-release";
        durable.static = "previous-static";
        durable.database = "previous-database";
        durable.vault = "previous-vault";
        calls.push("rollback-mutated-all-durable-state");
        throw primary;
      },
      recoverAndVerifyPrevious: () => recoverFailedRollback({
        stopAttempted,
        mutationStarted,
      }, {
        recoverUnchangedRelease: () => { calls.push("unexpected-unchanged-recovery"); },
        stopMutatedRelease: () => { calls.push("stop-mutated-rollback-target"); },
        restoreCurrentRelease: () => {
          calls.push("restore-preserved-current-pointers-database-and-vault");
          Object.assign(durable, preserved);
        },
        startCurrentRelease: () => {
          calls.push("start-current-release");
          expect(durable).toEqual(preserved);
        },
        verifyCurrentRelease: () => {
          calls.push("verify-current-release");
          expect(durable).toEqual(preserved);
        },
      }),
    });

    await expect(attempt).rejects.toBe(primary);
    expect(durable).toEqual(preserved);
    expect(calls).toEqual([
      "rollback-stop-clean",
      "rollback-mutated-all-durable-state",
      "stop-mutated-rollback-target",
      "restore-preserved-current-pointers-database-and-vault",
      "start-current-release",
      "verify-current-release",
    ]);
  });

  test("rollback recovery couples the primary and recovery failures", async () => {
    const primary = new Error("rollback mutation failed");
    const recovery = new Error("preserved current database could not be restored");
    let caught: unknown;
    try {
      await executePreparedDeploymentBoundary({
        stopAndProveClean: () => undefined,
        applyAndVerify: () => { throw primary; },
        recoverAndVerifyPrevious: () => recoverFailedRollback({
          stopAttempted: true,
          mutationStarted: true,
        }, {
          recoverUnchangedRelease: () => undefined,
          stopMutatedRelease: () => undefined,
          restoreCurrentRelease: () => { throw recovery; },
          startCurrentRelease: () => undefined,
          verifyCurrentRelease: () => undefined,
        }),
      });
    } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(FailClosedReleaseRecoveryError);
    expect((caught as FailClosedReleaseRecoveryError).releaseFailure).toBe(primary);
    expect((caught as FailClosedReleaseRecoveryError).recoveryFailure).toBe(recovery);
  });

  test("SIGTERM during post-stop mutation is converted into fail-closed recovery", async () => {
    const { workspace } = fixture();
    const stoppedPath = join(workspace, "stopped");
    const recoveredPath = join(workspace, "recovered");
    const failurePath = join(workspace, "failure");
    const functionalPath = join(process.cwd(), "scripts/release/functional-release.ts");
    const boundaryPath = join(process.cwd(), "scripts/release/ReleaseExecutionBoundary.ts");
    const child = Bun.spawn([process.execPath, "--eval", `
      import { writeFileSync } from "node:fs";
      import { executePreparedDeploymentBoundary } from ${JSON.stringify(functionalPath)};
      import { withCooperativeReleaseSignals } from ${JSON.stringify(boundaryPath)};
      try {
        await withCooperativeReleaseSignals((interruption) =>
          executePreparedDeploymentBoundary({
            stopAndProveClean: () => { writeFileSync(${JSON.stringify(stoppedPath)}, "stopped\\n"); },
            applyAndVerify: async () => {
              await new Promise((resolve) => interruption.signal.addEventListener("abort", resolve, { once: true }));
            },
            recoverAndVerifyPrevious: () => { writeFileSync(${JSON.stringify(recoveredPath)}, "recovered\\n"); },
          }, interruption),
        );
      } catch (error) {
        writeFileSync(${JSON.stringify(failurePath)}, error instanceof Error ? error.message : String(error));
        process.exitCode = 17;
      }
    `], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
    try {
      const deadline = performance.now() + 2_000;
      while (!existsSync(stoppedPath) && performance.now() < deadline) await Bun.sleep(10);
      expect(existsSync(stoppedPath)).toBe(true);
      child.kill("SIGTERM");
      expect(await child.exited).toBe(17);
      expect(readFileSync(recoveredPath, "utf8")).toBe("recovered\n");
      expect(readFileSync(failurePath, "utf8")).toContain("Release interrupted by SIGTERM");
    } finally {
      try { child.kill("SIGKILL"); } catch { /* already terminal */ }
      try { await child.exited; } catch { /* already terminal */ }
    }
  });

  test("post-commit rollback failure restores deployed receipt truth after current release recovery", async () => {
    const durable = { release: "current" };
    const receipt: { status: string; rolledBackAt?: string } = { status: "deployed" };
    const postCommitFailure = new Error("signal after rolled_back receipt commit");
    const attempt = executePreparedDeploymentBoundary({
      stopAndProveClean: () => undefined,
      applyAndVerify: () => {
        durable.release = "previous";
        receipt.status = "rolled_back";
        receipt.rolledBackAt = "2026-07-21T00:00:00.000Z";
        throw postCommitFailure;
      },
      recoverAndVerifyPrevious: () => { durable.release = "current"; },
    });
    await expect(attempt).rejects.toBe(postCommitFailure);
    restoreDeploymentReceiptAfterFailedRollbackCommit(receipt);
    expect(durable.release).toBe("current");
    expect(receipt).toEqual({ status: "deployed" });
  });

  test("deploy boundary repairs observed post-commit pointer drift before identity verification", async () => {
    const pointer = (applicationTarget: string, staticReleaseId: string): ReleasePointerSnapshot => ({
      application: {
        kind: "symlink",
        target: applicationTarget,
        device: "8",
        inode: "1",
      },
      staticReleaseId,
      staticManifestSha256: `${staticReleaseId}-manifest`,
    });
    const previous = pointer("/releases/previous", "static-previous");
    const candidate = pointer("/releases/candidate", "static-candidate");
    let observed = structuredClone(previous);
    const calls: string[] = [];
    const postCommitFailure = new Error("static pointer fsync failed after atomic commit");
    let now = 0;

    const attempt = executePreparedDeploymentBoundary({
      stopAndProveClean: () => { calls.push("stop-clean"); },
      applyAndVerify: () => {
        calls.push("commit-candidate-pointers");
        observed = structuredClone(candidate);
        // Simulates an operation that committed before returning to the caller,
        // so no post-return mutation flag can be trusted.
        throw postCommitFailure;
      },
      recoverAndVerifyPrevious: async () => {
        await reconcileObservedReleasePointerDrift(previous, {
          inspect: () => structuredClone(observed),
          restoreApplication: () => {
            calls.push("restore-observed-application-drift");
            observed = { ...observed, application: structuredClone(previous.application) };
          },
          restoreStatic: () => {
            calls.push("restore-observed-static-drift");
            observed = {
              ...observed,
              staticReleaseId: previous.staticReleaseId,
              staticManifestSha256: previous.staticManifestSha256,
            };
          },
        });
        await waitForExpectedTiScaleStartup({
          previousInvocationId: "invocation-before-stop",
          databaseSchema: 37,
          pointers: previous,
        }, {
          timeoutMs: 100,
          pollIntervalMs: 10,
          now: () => now,
          sleep: (milliseconds) => { now += milliseconds; },
          observe: () => {
            calls.push("verify-restarted-identity");
            return {
              activeState: "active",
              mainPid: 711,
              invocationId: "invocation-after-recovery",
              healthStatus: 200,
              semanticStatus: "healthy",
              readinessStatus: 200,
              readinessSemanticStatus: "healthy",
              databaseHealthy: true,
              databaseSchema: 37,
              pointers: structuredClone(observed),
              controlGroup: "/system.slice/ti-scale.service",
              controlGroupProcessIds: [711],
              listenerProcessIds: [711],
            };
          },
        });
      },
    });

    await expect(attempt).rejects.toBe(postCommitFailure);
    expect(observed).toEqual(previous);
    expect(calls).toEqual([
      "stop-clean",
      "commit-candidate-pointers",
      "restore-observed-application-drift",
      "restore-observed-static-drift",
      "verify-restarted-identity",
    ]);
  });

  test("pointer reconciliation always resumes post-exchange application cleanup even when live identity is exact", async () => {
    const expected: ReleasePointerSnapshot = {
      application: {
        kind: "symlink",
        target: "/releases/current",
        device: "8",
        inode: "7",
      },
      staticReleaseId: "static-current",
      staticManifestSha256: "static-current-manifest",
    };
    const calls: string[] = [];
    const observed = await reconcileObservedReleasePointerDrift(expected, {
      inspect: () => structuredClone(expected),
      reconcileApplication: () => { calls.push("resume-post-exchange-cleanup"); },
      restoreApplication: () => { calls.push("unexpected-application-restore"); },
      restoreStatic: () => { calls.push("unexpected-static-restore"); },
    });
    expect(observed).toEqual(expected);
    expect(calls).toEqual(["resume-post-exchange-cleanup"]);
  });

  test("startup verification allows measured cold-start progress but requires a new exact identity", async () => {
    const pointers: ReleasePointerSnapshot = {
      application: {
        kind: "symlink",
        target: "/releases/candidate",
        device: "8",
        inode: "4",
      },
      staticReleaseId: "candidate",
      staticManifestSha256: "candidate-manifest",
    };
    const observation = (
      values: Partial<TiScaleStartupObservation>,
    ): TiScaleStartupObservation => ({
      activeState: "activating",
      mainPid: 0,
      invocationId: "",
      healthStatus: 0,
      semanticStatus: "unavailable",
      readinessStatus: 0,
      readinessSemanticStatus: "unavailable",
      databaseHealthy: false,
      databaseSchema: null,
      pointers,
      controlGroup: "/system.slice/ti-scale.service",
      controlGroupProcessIds: [],
      listenerProcessIds: [],
      ...values,
    });
    const observations = [
      observation({}),
      observation({ activeState: "active", mainPid: 812, invocationId: "new-invocation" }),
      observation({
        activeState: "active",
        mainPid: 812,
        invocationId: "new-invocation",
        healthStatus: 200,
        semanticStatus: "healthy",
        readinessStatus: 200,
        readinessSemanticStatus: "healthy",
        databaseHealthy: true,
        databaseSchema: 37,
        // The systemd MainPID is the Bun runner while its child owns 3132;
        // both must be members of ti-scale.service's cgroup.
        controlGroupProcessIds: [812, 813],
        listenerProcessIds: [813],
      }),
    ];
    let now = 0;
    const progress: number[] = [];
    const result = await waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 40,
      pollIntervalMs: 10,
      now: () => now,
      sleep: (milliseconds) => { now += milliseconds; },
      observe: () => observations.shift()!,
      onProgress: (_value, elapsed) => { progress.push(elapsed); },
    });
    expect(result.invocationId).toBe("new-invocation");
    expect(progress).toEqual([0, 10]);
    expect(releaseStartupTimeoutMs(undefined)).toBe(240_000);
    expect(releaseStartupTimeoutMs("300000")).toBe(300_000);
    expect(() => releaseStartupTimeoutMs("120000")).toThrow("between 180000 and 900000");

    let wrongStatusNow = 0;
    await expect(waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 10,
      pollIntervalMs: 10,
      now: () => wrongStatusNow,
      sleep: (milliseconds) => { wrongStatusNow += milliseconds; },
      observe: () => observation({
        activeState: "active",
        mainPid: 899,
        invocationId: "new-but-wrong-semantic-status",
        healthStatus: 200,
        semanticStatus: "ok",
        readinessStatus: 200,
        readinessSemanticStatus: "healthy",
        databaseHealthy: true,
        databaseSchema: 37,
        controlGroupProcessIds: [899],
        listenerProcessIds: [899],
      }),
    })).rejects.toThrow("did not reach the expected active identity");

    let degradedReadinessNow = 0;
    await expect(waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 10,
      pollIntervalMs: 10,
      now: () => degradedReadinessNow,
      sleep: (milliseconds) => { degradedReadinessNow += milliseconds; },
      observe: () => observation({
        activeState: "active",
        mainPid: 898,
        invocationId: "new-but-execution-degraded",
        healthStatus: 200,
        semanticStatus: "healthy",
        readinessStatus: 200,
        readinessSemanticStatus: "degraded",
        databaseHealthy: true,
        databaseSchema: 37,
        controlGroupProcessIds: [898],
        listenerProcessIds: [898],
      }),
    })).rejects.toThrow("did not reach the expected active identity");

    await expect(waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 10,
      pollIntervalMs: 10,
      observe: () => observation({
        activeState: "active",
        mainPid: 900,
        invocationId: "old-invocation",
        healthStatus: 200,
        semanticStatus: "healthy",
        readinessStatus: 200,
        readinessSemanticStatus: "healthy",
        databaseHealthy: true,
        databaseSchema: 37,
      }),
    })).rejects.toThrow("reused the pre-stop systemd invocation");
  });

  test("startup rejects listeners outside the expected systemd cgroup", async () => {
    const pointers: ReleasePointerSnapshot = {
      application: {
        kind: "symlink",
        target: "/releases/candidate",
        device: "ignored",
        inode: "ignored",
      },
      staticReleaseId: "candidate",
      staticManifestSha256: "candidate-manifest",
    };
    let now = 0;
    await expect(waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 20,
      pollIntervalMs: 10,
      now: () => now,
      sleep: (milliseconds) => { now += milliseconds; },
      observe: () => ({
        activeState: "active",
        mainPid: 1_201,
        invocationId: "new-invocation",
        healthStatus: 200,
        semanticStatus: "healthy",
        readinessStatus: 200,
        readinessSemanticStatus: "healthy",
        databaseHealthy: true,
        databaseSchema: 37,
        pointers,
        controlGroup: "/system.slice/ti-scale.service",
        controlGroupProcessIds: [1_201],
        listenerProcessIds: [9_999],
      }),
    })).rejects.toThrow("did not reach the expected active identity");

    now = 0;
    await expect(waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 20,
      pollIntervalMs: 10,
      now: () => now,
      sleep: (milliseconds) => { now += milliseconds; },
      observe: () => ({
        activeState: "active",
        mainPid: 1_201,
        invocationId: "new-invocation",
        healthStatus: 200,
        semanticStatus: "healthy",
        readinessStatus: 200,
        readinessSemanticStatus: "healthy",
        databaseHealthy: true,
        databaseSchema: 37,
        pointers,
        controlGroup: "/system.slice/not-ti-scale.service",
        controlGroupProcessIds: [1_201],
        listenerProcessIds: [1_201],
      }),
    })).rejects.toThrow("did not reach the expected active identity");
  });

  test("startup deadline aborts an observation that ignores its signal", async () => {
    const pointers: ReleasePointerSnapshot = {
      application: {
        kind: "symlink",
        target: "/releases/candidate",
        device: "ignored",
        inode: "ignored",
      },
      staticReleaseId: "candidate",
      staticManifestSha256: "candidate-manifest",
    };
    const startedAt = performance.now();
    await expect(waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 25,
      pollIntervalMs: 5,
      observe: () => new Promise<TiScaleStartupObservation>(() => {
        // Deliberately never settles and does not observe AbortSignal.
      }),
    })).rejects.toThrow("did not reach the expected active identity");
    expect(performance.now() - startedAt).toBeLessThan(500);
  });

  test("startup subprocess observations are killed within their own hard timeout", async () => {
    const startedAt = performance.now();
    await expect(runRequiredBounded(
      ["/usr/bin/sleep", "5"],
      25,
      new AbortController().signal,
    )).rejects.toThrow("sleep exceeded its 25ms release deadline");
    expect(performance.now() - startedAt).toBeLessThan(500);
  });

  test("startup preserves the exact parent signal cause when interrupted during sleep", async () => {
    const pointers: ReleasePointerSnapshot = {
      application: {
        kind: "symlink",
        target: "/releases/candidate",
        device: "ignored",
        inode: "ignored",
      },
      staticReleaseId: "candidate",
      staticManifestSha256: "candidate-manifest",
    };
    const controller = new AbortController();
    const interrupted = new ReleaseInterruptedError("SIGTERM");
    await expect(waitForExpectedTiScaleStartup({
      previousInvocationId: "old-invocation",
      databaseSchema: 37,
      pointers,
    }, {
      timeoutMs: 100,
      pollIntervalMs: 10,
      signal: controller.signal,
      observe: () => ({
        activeState: "activating",
        mainPid: 0,
        invocationId: "",
        healthStatus: 0,
        semanticStatus: "unavailable",
        readinessStatus: 0,
        readinessSemanticStatus: "unavailable",
        databaseHealthy: false,
        databaseSchema: null,
        pointers,
        controlGroup: "/system.slice/ti-scale.service",
        controlGroupProcessIds: [],
        listenerProcessIds: [],
      }),
      sleep: () => { controller.abort(interrupted); },
    })).rejects.toBe(interrupted);
  });

  test("coupled recovery evidence retains both failures and legacy invariant status", async () => {
    const releaseFailure = new Error("primary deployment failure");
    const legacyFailure = new ProtectedLegacyInvariantError(
      "changed_or_unhealthy",
      {
        activeState: "active",
        mainPid: 1,
        invocationId: "before",
        healthStatus: 200,
        semanticStatus: "ok",
      },
      {
        activeState: "active",
        mainPid: 2,
        invocationId: "after",
        healthStatus: 200,
        semanticStatus: "ok",
      },
      "protected legacy identity changed",
    );
    let coupled: unknown;
    try {
      await executeWithFailClosedReleaseRecovery(
        () => { throw releaseFailure; },
        () => { throw legacyFailure; },
      );
    } catch (error) { coupled = error; }
    expect(coupled).toBeInstanceOf(FailClosedReleaseRecoveryError);
    const failure = coupled as FailClosedReleaseRecoveryError;
    expect(failure.releaseFailure).toBe(releaseFailure);
    expect(failure.recoveryFailure).toBe(legacyFailure);
    expect(safeErrorRecord(failure).cause?.message).toBe("primary deployment failure");
    expect(safeErrorRecord(failure.recoveryFailure).message).toBe("protected legacy identity changed");
    expect(legacyVerificationFromError(failure)).toBe("changed_or_unhealthy");
  });
});
