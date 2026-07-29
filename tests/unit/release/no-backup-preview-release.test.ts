import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertNoBackupForwardReceiptSchemaBoundary,
  assertNoBackupPayloadInventoryEmpty,
  assertNoBackupPayloadInventoryUnchanged,
  attestedNoBackupForwardSchemas,
  captureNoBackupPayloadInventory,
  discardFailedPreSchemaCandidateArtifacts,
  executeNoBackupPreviewPhaseSequence,
  isStandaloneNoBackupForwardReceipt,
  NO_BACKUP_CURRENT_DEPLOYMENT_MODE,
  NO_BACKUP_FORWARD_RECEIPT_SCHEMA,
  NO_BACKUP_PAYLOAD_ROOTS,
  NO_BACKUP_PREVIEW_RECEIPT_SCHEMA,
  NO_BACKUP_STANDALONE_RELEASE_OBSERVER,
  noBackupObserverProofDetail,
  noBackupObserverProofSha256FromDetail,
  noBackupAuthenticationSessionReady,
  noBackupTargetStartMode,
  noBackupStopSnapshotFromServiceProperties,
  noBackupRecoveryDirection,
  noBackupForwardDeploymentSchemaBoundary,
  noBackupPreviewUsage,
  NO_BACKUP_SOURCE_SCHEMA,
  NO_BACKUP_TARGET_SCHEMA,
  parseNoBackupPreviewArguments,
  resolveNoBackupReleaseObserverProof,
  type NoBackupPreviewReceipt,
  verifyNoBackupTargetApplicationForCommit,
} from "../../../scripts/release/NoBackupPreviewRelease";
import {
  attestReleaseMigrationCeiling,
} from "../../../scripts/release/ReleaseMigrationAttestation";
import {
  canonicalApplicationTreeFingerprint,
  stageServerRelease,
} from "../../../scripts/release/FunctionalReleasePrimitives";
import {
  executeNoBackupForwardOnlyController,
} from "../../../scripts/release/NoBackupForwardOnlyController";
import {
  appendFunctionalReleaseTransactionRecord,
  canonicalReleaseTransactionJson,
  commitFunctionalReleaseTransactionTarget,
  completeFunctionalReleaseMutation,
  createFunctionalReleaseTransactionJournal,
  discoverIncompleteFunctionalReleaseTransactions,
  prepareFunctionalReleaseMutation,
  readFunctionalReleaseTransactionJournal,
  releaseTransactionSha256,
} from "../../../scripts/release/DurableReleaseTransaction";
import { assertReleaseServiceStartAdmitted } from
  "../../../scripts/release/ReleaseServiceStartAdmission";
import { RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL } from
  "../../../scripts/release/ReleaseStartupMutationBarrier";
import {
  RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT,
} from "../../../scripts/release/ReleaseServiceStartAdmissionBundle";
import { runDatabaseCli } from "../../../server/db/cli";
import { createDatabaseConnection } from "../../../server/db/connection";
import { DATABASE_MIGRATIONS } from "../../../server/db/migrations";
import { migrateDatabase } from "../../../server/db/migrations/runner";
import type { Migration } from "../../../server/db/types";
import { StaticArtifactReleaseStore } from
  "../../../server/static-release";

const temporaryDirectories: string[] = [];

function temporaryDirectory(prefix: string): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

function withoutBackupRequirement(migration: Migration): Migration {
  const {
    requiresVerifiedBackup: _requiresVerifiedBackup,
    ...noBackupMigration
  } = migration;
  return noBackupMigration;
}

function schemaVersion(path: string): number {
  const database = createDatabaseConnection({
    filename: path,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    return Number((database.prepare(
      "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
    ).get() as { readonly version: number }).version);
  } finally {
    database.close();
  }
}

async function failedCandidateFixture() {
  const root = temporaryDirectory(
    "ti-scale-no-backup-failed-candidate-",
  );
  const serverReleaseRoot = join(root, "ti-scale-server-releases");
  const staticReleaseRoot = join(root, "ti-scale-static-releases");
  const activeServerSource = join(root, "active-server-source");
  const candidateServerSource = join(root, "candidate-server-source");
  for (const [source, marker] of [
    [activeServerSource, "active"],
    [candidateServerSource, "candidate"],
  ] as const) {
    mkdirSync(join(source, "server"), { recursive: true });
    writeFileSync(
      join(source, "package.json"),
      `${JSON.stringify({ name: `ti-scale-${marker}` })}\n`,
    );
    writeFileSync(
      join(source, "server", "index.ts"),
      `export const release = ${JSON.stringify(marker)};\n`,
    );
  }
  const activeServer = await stageServerRelease({
    sourceRoot: activeServerSource,
    releaseRoot: serverReleaseRoot,
    releaseId: "active-release",
  });
  const candidateServer = await stageServerRelease({
    sourceRoot: candidateServerSource,
    releaseRoot: serverReleaseRoot,
    releaseId: "candidate-release",
  });

  const activeStaticSource = join(root, "active-static-source");
  const candidateStaticSource = join(root, "candidate-static-source");
  mkdirSync(activeStaticSource);
  mkdirSync(candidateStaticSource);
  writeFileSync(
    join(activeStaticSource, "index.html"),
    "<main>active</main>\n",
  );
  writeFileSync(
    join(candidateStaticSource, "index.html"),
    "<main>candidate</main>\n",
  );
  const staticStore = new StaticArtifactReleaseStore({
    releaseRoot: staticReleaseRoot,
  });
  const activeStatic = staticStore.stageRelease({
    releaseId: "active-release",
    sourceDirectory: activeStaticSource,
  });
  staticStore.activateRelease(activeStatic.releaseId);
  const candidateStatic = staticStore.stageRelease({
    releaseId: "candidate-release",
    sourceDirectory: candidateStaticSource,
  });
  return {
    serverReleaseRoot,
    staticReleaseRoot,
    activeServer,
    candidateServer,
    staticStore,
    activeStatic,
    candidateStatic,
  };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("metadata-journaled no-backup preview release", () => {
  test("requires the exact configured unauthenticated session contract", () => {
    expect(noBackupAuthenticationSessionReady({
      statusCode: 200,
      body: {
        schemaVersion: "2.4",
        configured: true,
        authenticated: false,
      },
    })).toBe(true);
    for (const response of [
      {
        statusCode: 503,
        body: {
          schemaVersion: "2.4",
          configured: true,
          authenticated: false,
        },
      },
      {
        statusCode: 200,
        body: {
          schemaVersion: "2.4",
          configured: false,
          authenticated: false,
        },
      },
      {
        statusCode: 200,
        body: {
          schemaVersion: "2.4",
          configured: true,
          authenticated: true,
        },
      },
      {
        statusCode: 200,
        body: {
          schemaVersion: "2.4",
          configured: true,
          authenticated: false,
          unexpected: "field",
        },
      },
    ] as const) {
      expect(noBackupAuthenticationSessionReady(response)).toBe(false);
    }
  });

  test("new forward receipts use a standalone observer without consulting another service", async () => {
    const receipt = {
      schemaVersion: NO_BACKUP_FORWARD_RECEIPT_SCHEMA,
      deploymentMode: NO_BACKUP_CURRENT_DEPLOYMENT_MODE,
      releaseObserver: NO_BACKUP_STANDALONE_RELEASE_OBSERVER,
    } as unknown as NoBackupPreviewReceipt;
    let historicalCaptureCalls = 0;

    expect(isStandaloneNoBackupForwardReceipt(receipt)).toBe(true);
    await expect(resolveNoBackupReleaseObserverProof(receipt, async () => {
      historicalCaptureCalls += 1;
      throw new Error("new receipt must not query a historical observer");
    })).resolves.toEqual(NO_BACKUP_STANDALONE_RELEASE_OBSERVER);
    expect(historicalCaptureCalls).toBe(0);

    const serialized = JSON.stringify(receipt);
    expect(serialized).not.toContain("chillspwn");
    expect(serialized).not.toContain("3131");
    expect(serialized).not.toContain("cutoverEligible");
    expect(serialized).toContain('"deploymentMode":"current_service"');
    expect(serialized).toContain('"externalServiceDependency":"none"');
  });

  test("historical v1 receipts retain their exact observer recovery path", async () => {
    const before = {
      activeState: "active",
      mainPid: 3131,
      invocationId: "a".repeat(32),
      healthStatus: 200,
      semanticStatus: "ok",
    };
    const after = {
      ...before,
      invocationId: "b".repeat(32),
    };
    const receipt = {
      schemaVersion: NO_BACKUP_PREVIEW_RECEIPT_SCHEMA,
      cutoverEligible: false,
      chillspwnBefore: before,
    } as unknown as NoBackupPreviewReceipt;
    let historicalCaptureCalls = 0;

    expect(isStandaloneNoBackupForwardReceipt(receipt)).toBe(false);
    await expect(resolveNoBackupReleaseObserverProof(receipt, async () => {
      historicalCaptureCalls += 1;
      return after;
    })).resolves.toEqual(after);
    expect(historicalCaptureCalls).toBe(1);
  });

  test("uses the v2 observer hash while preserving the v1 journal hash field", () => {
    const proofSha256 = "c".repeat(64);
    const currentReceipt = {
      schemaVersion: NO_BACKUP_FORWARD_RECEIPT_SCHEMA,
      deploymentMode: NO_BACKUP_CURRENT_DEPLOYMENT_MODE,
      releaseObserver: NO_BACKUP_STANDALONE_RELEASE_OBSERVER,
    } as unknown as NoBackupPreviewReceipt;
    const historicalReceipt = {
      schemaVersion: NO_BACKUP_PREVIEW_RECEIPT_SCHEMA,
      cutoverEligible: false,
      chillspwnBefore: {
        activeState: "active",
        mainPid: 3131,
        invocationId: "a".repeat(32),
        healthStatus: 200,
        semanticStatus: "ok",
      },
    } as unknown as NoBackupPreviewReceipt;

    const currentDetail = noBackupObserverProofDetail(
      currentReceipt,
      proofSha256,
    );
    const historicalDetail = noBackupObserverProofDetail(
      historicalReceipt,
      proofSha256,
    );

    expect(currentDetail).toEqual({ observerProofSha256: proofSha256 });
    expect(noBackupObserverProofSha256FromDetail(
      currentDetail,
      currentReceipt,
    )).toBe(proofSha256);
    expect(historicalDetail).toEqual({
      legacyIdentitySha256: proofSha256,
    });
    expect(noBackupObserverProofSha256FromDetail(
      historicalDetail,
      historicalReceipt,
    )).toBe(proofSha256);
  });

  test("operator help describes a current forward deployment instead of a preview", () => {
    const usage = noBackupPreviewUsage();
    expect(usage).toContain("no-backup forward deployment");
    expect(usage).toContain("current");
    expect(usage).not.toContain("preview deployment");
    expect(usage).not.toContain("schema 48");
  });

  test("re-verifies the manifest-bound target and records its complete application-tree fingerprint", async () => {
    const root = temporaryDirectory(
      "ti-scale-no-backup-target-commit-identity-",
    );
    const source = join(root, "source");
    mkdirSync(join(source, "server"), { recursive: true });
    writeFileSync(join(source, "package.json"), "{\"name\":\"target\"}\n");
    writeFileSync(
      join(source, "server", "index.ts"),
      "export const target = true;\n",
    );
    const release = await stageServerRelease({
      sourceRoot: source,
      releaseRoot: join(root, "releases"),
      releaseId: "target-release",
    });

    const completeTreeSha256 = await canonicalApplicationTreeFingerprint(
      release.releaseDirectory,
    );
    expect(completeTreeSha256).not.toBe(release.manifest.treeSha256);
    await expect(verifyNoBackupTargetApplicationForCommit({
      releaseId: release.releaseId,
      applicationTarget: release.releaseDirectory,
      serverReleasePath: release.releaseDirectory,
      manifestSha256: release.manifestSha256,
      manifestTreeSha256: release.manifest.treeSha256,
    })).resolves.toBe(completeTreeSha256);

    writeFileSync(
      join(release.releaseDirectory, "server", "index.ts"),
      "export const target = false;\n",
    );
    await expect(verifyNoBackupTargetApplicationForCommit({
      releaseId: release.releaseId,
      applicationTarget: release.releaseDirectory,
      serverReleasePath: release.releaseDirectory,
      manifestSha256: release.manifestSha256,
      manifestTreeSha256: release.manifest.treeSha256,
    })).rejects.toThrow(
      "Server release tree does not match its immutable manifest",
    );
  });

  test("normalizes only the cleaned inactive Ti-Scale unit and still inspects its cgroup and listener", () => {
    const inspectedControlGroups: string[] = [];
    let listenerChecks = 0;
    const inactive = noBackupStopSnapshotFromServiceProperties({
      activeState: "inactive",
      mainPid: 0,
      invocationId: "",
      controlGroup: "",
    }, {
      controlGroupProcessIds: (controlGroup) => {
        inspectedControlGroups.push(controlGroup);
        return [];
      },
      portListening: () => {
        listenerChecks += 1;
        return false;
      },
    });
    expect(inactive).toEqual({
      activeState: "inactive",
      mainPid: 0,
      controlGroup: "/system.slice/ti-scale.service",
      controlGroupProcessIds: [],
      portListening: false,
    });
    expect(inspectedControlGroups).toEqual([
      "/system.slice/ti-scale.service",
    ]);
    expect(listenerChecks).toBe(1);

    for (const properties of [
      {
        activeState: "failed",
        mainPid: 0,
        invocationId: "",
        controlGroup: "",
      },
      {
        activeState: "inactive",
        mainPid: 3132,
        invocationId: "",
        controlGroup: "",
      },
      {
        activeState: "inactive",
        mainPid: 0,
        invocationId: "",
        controlGroup: "/unexpected.slice/ti-scale.service",
      },
    ] as const) {
      expect(noBackupStopSnapshotFromServiceProperties(properties, {
        controlGroupProcessIds: () => [],
        portListening: () => false,
      }).controlGroup).toBe(properties.controlGroup);
    }
  });

  test("requires execution, exact release confirmation, and explicit no-backup acknowledgement", () => {
    expect(parseNoBackupPreviewArguments([
      "deploy",
      "--execute",
      "--release-id",
      "agent-llm-roster-v48",
      "--confirm",
      "agent-llm-roster-v48",
      "--acknowledge-no-backup-risk",
    ])).toEqual({
      command: "deploy",
      releaseId: "agent-llm-roster-v48",
      confirmation: "agent-llm-roster-v48",
      execute: true,
      noBackupRiskAcknowledged: true,
    });

    expect(() => parseNoBackupPreviewArguments([
      "deploy",
      "--execute",
      "--release-id",
      "agent-llm-roster-v48",
      "--confirm",
      "agent-llm-roster-v48",
    ])).toThrow("--acknowledge-no-backup-risk");
    expect(() => parseNoBackupPreviewArguments([
      "deploy",
      "--execute",
      "--release-id",
      "agent-llm-roster-v48",
      "--confirm",
      "different-release",
      "--acknowledge-no-backup-risk",
    ])).toThrow("--confirm must exactly match --release-id");
    expect(parseNoBackupPreviewArguments([
      "recover",
      "--execute",
      "--release-id",
      "agent-llm-roster-v48",
      "--confirm",
      "agent-llm-roster-v48",
      "--acknowledge-no-backup-risk",
    ]).command).toBe("recover");
  });

  test("covers every dedicated backup and rehearsal root without backup-producing code paths", () => {
    expect(NO_BACKUP_PAYLOAD_ROOTS).toEqual([
      "/var/backups/ti-scale",
      "/var/lib/ti-scale/backups",
      "/var/lib/ti-scale/data/backups",
      "/var/lib/ti-scale/data/migration-backups",
      "/var/lib/ti-scale/hotfix-backups",
      "/var/lib/ti-scale/imports/historical-sqlite-snapshots",
      "/var/lib/ti-scale/rehearsals",
      "/var/lib/ti-scale/release-rehearsal",
      "/var/lib/ti-scale/staging",
    ]);
    const controller = readFileSync(
      join(process.cwd(), "scripts/release/NoBackupPreviewRelease.ts"),
      "utf8",
    );
    expect(controller).not.toContain("VACUUM INTO");
    expect(controller).not.toContain("--backup-dir");
    expect(controller).not.toContain("createVerifiedBackup");
    expect(controller).not.toContain(
      '"/var/backups/ti-scale/releases"',
    );
    expect(controller).not.toContain("functional-release-backup-prune");
    expect(controller).not.toContain("rollback-target-maintenance");
    expect(controller).not.toContain("server-release-prune");
    expect(controller).not.toContain('from "./functional-release"');
    expect(controller).toContain(
      'from "./ForwardOnlyReleaseRuntimeBoundary"',
    );
    expect(controller).toContain(
      "assertReleaseServiceStartAdmissionInstallationCommitted",
    );
    expect(controller).toContain(
      '"/var/lib/ti-scale/release-transactions"',
    );
    expect(RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT).toBe(
      "/var/lib/ti-scale/release-transactions",
    );
    const admissionHelper = readFileSync(
      join(process.cwd(), "scripts/release/service-start-admission.ts"),
      "utf8",
    );
    expect(admissionHelper).toContain(
      '"/var/lib/ti-scale/release-transactions"',
    );
    expect(admissionHelper).not.toContain(
      '"/var/backups/ti-scale/releases"',
    );
    const installation = readFileSync(
      join(
        process.cwd(),
        "scripts/release/ReleaseServiceStartAdmissionInstallation.ts",
      ),
      "utf8",
    );
    expect(installation).not.toContain(
      "writeDurableFileAtomically(artifact.targetPath",
    );
    expect(installation).toContain("O_NOFOLLOW");
    const systemdDropIn = readFileSync(
      join(
        process.cwd(),
        "deployment/systemd/ti-scale.service.d/" +
          "10-release-start-admission.conf",
      ),
      "utf8",
    );
    expect(systemdDropIn).toContain(
      "RequiresMountsFor=/var/lib/ti-scale/release-transactions",
    );
    expect(systemdDropIn).not.toContain("/var/backups/ti-scale");
    expect(controller).toContain("--no-backup");
    expect(controller).toContain("--acknowledge-no-backup-risk");
  });

  test("ignores an unpublished atomic metadata opening directory", () => {
    const root = temporaryDirectory(
      "ti-scale-no-backup-metadata-publication-",
    );
    const opening = join(
      root,
      ".release-a.123." +
        "01234567-89ab-4cde-8fab-0123456789ab.opening",
    );
    mkdirSync(
      join(opening, "transaction-journal"),
      { recursive: true, mode: 0o700 },
    );
    writeFileSync(
      join(opening, "transaction-journal", "receipt-only"),
      "unpublished\n",
    );
    expect(discoverIncompleteFunctionalReleaseTransactions(root))
      .toEqual([]);
  });

  test("releases the maintenance boundary before any service-start phase", async () => {
    const phases: string[] = [];
    let maintenanceActive = false;

    await executeNoBackupPreviewPhaseSequence({
      stop: () => {
        phases.push("stop");
      },
      withMaintenance: async (operation) => {
        phases.push("maintenance_acquired");
        maintenanceActive = true;
        try {
          return await operation();
        } finally {
          maintenanceActive = false;
          phases.push("maintenance_released");
        }
      },
      migrate: () => {
        expect(maintenanceActive).toBe(true);
        phases.push("migrate");
      },
      commitTarget: () => {
        expect(maintenanceActive).toBe(true);
        phases.push("commit_target");
      },
      startAndFinalize: () => {
        expect(maintenanceActive).toBe(false);
        phases.push("start");
      },
    });

    expect(phases).toEqual([
      "stop",
      "maintenance_acquired",
      "migrate",
      "commit_target",
      "maintenance_released",
      "start",
    ]);
  });

  test("does not enter the service-start phase when maintenance work fails", async () => {
    const phases: string[] = [];
    await expect(executeNoBackupPreviewPhaseSequence({
      stop: () => {
        phases.push("stop");
      },
      withMaintenance: async (operation) => {
        phases.push("maintenance_acquired");
        try {
          return await operation();
        } finally {
          phases.push("maintenance_released");
        }
      },
      migrate: () => {
        phases.push("migrate");
        throw new Error("injected migration failure");
      },
      commitTarget: () => {
        phases.push("commit_target");
      },
      startAndFinalize: () => {
        phases.push("start");
      },
    })).rejects.toThrow("injected migration failure");
    expect(phases).toEqual([
      "stop",
      "maintenance_acquired",
      "migrate",
      "maintenance_released",
    ]);
  });

  test("inventories every regular payload, including source/static copies and SQLite sidecars", () => {
    const root = temporaryDirectory("ti-scale-no-backup-inventory-");
    mkdirSync(join(root, "server-source-copy"), { recursive: true });
    mkdirSync(join(root, "static-copy"), { recursive: true });
    writeFileSync(join(root, "server-source-copy", "index.ts"), "export {};\n");
    writeFileSync(join(root, "static-copy", "app.js"), "export {};\n");
    writeFileSync(join(root, "state.sqlite-wal"), "wal");
    writeFileSync(join(root, "state.sqlite-shm"), "shm");
    writeFileSync(join(root, "payload.json"), "{}\n");

    const before = captureNoBackupPayloadInventory([root]);
    expect(before.entries.map((entry) => entry.path)).toEqual([
      join(root, "payload.json"),
      join(root, "server-source-copy", "index.ts"),
      join(root, "state.sqlite-shm"),
      join(root, "state.sqlite-wal"),
      join(root, "static-copy", "app.js"),
    ]);
    expect(before.entries.every((entry) =>
      /^[a-f0-9]{64}$/u.test(entry.sha256) &&
      Number.isFinite(entry.changedMs)
    )).toBe(true);

    mkdirSync(join(root, "unexpected-snapshot"), { recursive: true });
    writeFileSync(join(root, "unexpected-snapshot", "source.txt"), "copy");
    const after = captureNoBackupPayloadInventory([root]);
    expect(() => assertNoBackupPayloadInventoryUnchanged(before, after))
      .toThrow("created or changed a backup payload");
  });

  test("requires an empty backup payload inventory before production preparation", () => {
    const root = temporaryDirectory(
      "ti-scale-no-backup-empty-preflight-",
    );
    const empty = captureNoBackupPayloadInventory([root]);
    expect(() => assertNoBackupPayloadInventoryEmpty(empty))
      .not.toThrow();

    writeFileSync(join(root, "preexisting-backup.sqlite"), "payload");
    const nonempty = captureNoBackupPayloadInventory([root]);
    expect(() => assertNoBackupPayloadInventoryEmpty(nonempty))
      .toThrow("requires every configured backup payload root to be empty");
    expect(() =>
      assertNoBackupPayloadInventoryUnchanged(nonempty, nonempty)
    ).not.toThrow();
  });

  test("deletes an exact unreferenced failed candidate and is idempotent", async () => {
    const fixture = await failedCandidateFixture();
    const input = {
      serverReleaseRoot: fixture.serverReleaseRoot,
      staticReleaseRoot: fixture.staticReleaseRoot,
      activeApplicationTarget:
        fixture.activeServer.releaseDirectory,
      activeStaticReleaseId: fixture.activeStatic.releaseId,
      activeStaticManifestSha256:
        fixture.activeStatic.manifestSha256,
      candidateReleaseId: fixture.candidateServer.releaseId,
      candidateApplicationTarget:
        fixture.candidateServer.releaseDirectory,
      candidateServerManifestSha256:
        fixture.candidateServer.manifestSha256,
      candidateServerTreeSha256:
        fixture.candidateServer.manifest.treeSha256,
      candidateStaticManifestSha256:
        fixture.candidateStatic.manifestSha256,
    } as const;

    await expect(discardFailedPreSchemaCandidateArtifacts(input))
      .resolves.toEqual({
        staticReleaseDeleted: true,
        serverReleaseDeleted: true,
      });
    expect(existsSync(fixture.activeServer.releaseDirectory)).toBe(true);
    expect(existsSync(fixture.activeStatic.releaseDirectory)).toBe(true);
    expect(existsSync(fixture.candidateServer.releaseDirectory)).toBe(false);
    expect(existsSync(fixture.candidateStatic.releaseDirectory)).toBe(false);
    expect(fixture.staticStore.readActivePointer()).toMatchObject({
      activeReleaseId: fixture.activeStatic.releaseId,
      activeManifestSha256: fixture.activeStatic.manifestSha256,
    });

    await expect(discardFailedPreSchemaCandidateArtifacts(input))
      .resolves.toEqual({
        staticReleaseDeleted: false,
        serverReleaseDeleted: false,
      });

    symlinkSync(
      fixture.activeServer.releaseDirectory,
      fixture.candidateServer.releaseDirectory,
    );
    await expect(discardFailedPreSchemaCandidateArtifacts(input))
      .rejects.toThrow(
        "Failed candidate server release is not an exact immutable release directory",
      );
    expect(existsSync(fixture.activeServer.releaseDirectory)).toBe(true);
  });

  test("fails closed instead of deleting an active or pointer-retained release", async () => {
    const active = await failedCandidateFixture();
    await expect(discardFailedPreSchemaCandidateArtifacts({
      serverReleaseRoot: active.serverReleaseRoot,
      staticReleaseRoot: active.staticReleaseRoot,
      activeApplicationTarget: active.activeServer.releaseDirectory,
      activeStaticReleaseId: active.activeStatic.releaseId,
      activeStaticManifestSha256: active.activeStatic.manifestSha256,
      candidateReleaseId: active.activeServer.releaseId,
      candidateApplicationTarget: active.activeServer.releaseDirectory,
      candidateServerManifestSha256: active.activeServer.manifestSha256,
      candidateServerTreeSha256: active.activeServer.manifest.treeSha256,
      candidateStaticManifestSha256: active.activeStatic.manifestSha256,
    })).rejects.toThrow("must never delete the active server release");
    expect(existsSync(active.activeServer.releaseDirectory)).toBe(true);
    expect(existsSync(active.activeStatic.releaseDirectory)).toBe(true);

    const retained = await failedCandidateFixture();
    retained.staticStore.activateRelease(
      retained.candidateStatic.releaseId,
    );
    retained.staticStore.activateRelease(
      retained.activeStatic.releaseId,
    );
    await expect(discardFailedPreSchemaCandidateArtifacts({
      serverReleaseRoot: retained.serverReleaseRoot,
      staticReleaseRoot: retained.staticReleaseRoot,
      activeApplicationTarget: retained.activeServer.releaseDirectory,
      activeStaticReleaseId: retained.activeStatic.releaseId,
      activeStaticManifestSha256: retained.activeStatic.manifestSha256,
      candidateReleaseId: retained.candidateServer.releaseId,
      candidateApplicationTarget: retained.candidateServer.releaseDirectory,
      candidateServerManifestSha256:
        retained.candidateServer.manifestSha256,
      candidateServerTreeSha256:
        retained.candidateServer.manifest.treeSha256,
      candidateStaticManifestSha256:
        retained.candidateStatic.manifestSha256,
    })).rejects.toThrow("retained by the active pointer");
    expect(existsSync(retained.candidateServer.releaseDirectory)).toBe(true);
    expect(existsSync(retained.candidateStatic.releaseDirectory)).toBe(true);
  });

  test("the stable staging root catches future dated backup descendants", () => {
    const root = temporaryDirectory(
      "ti-scale-no-backup-staging-parent-",
    );
    const staging = join(root, "staging");
    mkdirSync(staging);
    const before = captureNoBackupPayloadInventory([staging]);
    const future = join(
      staging,
      "historical-attack-knowledge-20990101T000000Z",
      "base-backup",
    );
    mkdirSync(future, { recursive: true });
    writeFileSync(join(future, "canonical.sqlite"), "forbidden-copy");
    const after = captureNoBackupPayloadInventory([staging]);
    expect(() =>
      assertNoBackupPayloadInventoryUnchanged(before, after)
    ).toThrow("created or changed a backup payload");
  });

  test("refuses a configured payload root that is itself a symbolic link", () => {
    const root = temporaryDirectory("ti-scale-no-backup-symlink-root-");
    const real = join(root, "real");
    const linked = join(root, "configured-root");
    mkdirSync(real);
    writeFileSync(join(real, "payload.bin"), "payload");
    symlinkSync(real, linked);
    expect(() => captureNoBackupPayloadInventory([linked]))
      .toThrow("Configured no-backup payload root must not be a symbolic link");
  });

  test("refuses nested and dangling symbolic links in no-backup payload roots", () => {
    const root = temporaryDirectory("ti-scale-no-backup-nested-link-");
    const nested = join(root, "nested");
    mkdirSync(nested);
    symlinkSync(join(root, "missing-payload"), join(nested, "dangling"));
    expect(() => captureNoBackupPayloadInventory([root]))
      .toThrow("refuses nested symbolic links");
    rmSync(join(nested, "dangling"));
    const payload = join(root, "payload.bin");
    writeFileSync(payload, "payload");
    symlinkSync(payload, join(nested, "live-link"));
    expect(() => captureNoBackupPayloadInventory([root]))
      .toThrow("refuses nested symbolic links");
  });

  test("classifies every attested 47-to-60 migration boundary as forward-only", () => {
    const forwardSchemas = Array.from(
      { length: 13 },
      (_, index) => index + 48,
    );
    expect(noBackupRecoveryDirection(
      47,
      60,
      47,
      forwardSchemas,
    )).toBe("restore_source");
    for (const observedSchema of forwardSchemas) {
      expect(noBackupRecoveryDirection(
        47,
        60,
        observedSchema,
        forwardSchemas,
      )).toBe("complete_target");
    }
    expect(() => noBackupRecoveryDirection(47, 60, 46, forwardSchemas))
      .toThrow("cannot classify observed schema");
    expect(() => noBackupRecoveryDirection(47, 60, 61, forwardSchemas))
      .toThrow("cannot classify observed schema");
    expect(() => noBackupRecoveryDirection(
      47,
      60,
      52,
      forwardSchemas.filter((version) => version !== 52),
    )).toThrow("must include every schema");
  });

  test("classifies same-schema recovery only from durable target commitment", () => {
    expect(noBackupRecoveryDirection(60, 60, 60, [], false))
      .toBe("restore_source");
    expect(noBackupRecoveryDirection(60, 60, 60, [], true))
      .toBe("complete_target");
    expect(() => noBackupRecoveryDirection(60, 60, 60, []))
      .toThrow("requires durable target commitment state");
    expect(() => noBackupRecoveryDirection(60, 60, 59, [], false))
      .toThrow("cannot classify observed schema");
    expect(() => noBackupRecoveryDirection(60, 60, 61, [], true))
      .toThrow("cannot classify observed schema");
  });

  test("selects baseline migration and exact-ceiling source-only update boundaries", () => {
    expect(noBackupForwardDeploymentSchemaBoundary(
      NO_BACKUP_SOURCE_SCHEMA,
      NO_BACKUP_TARGET_SCHEMA,
    )).toEqual({
      sourceSchema: NO_BACKUP_SOURCE_SCHEMA,
      targetSchema: NO_BACKUP_TARGET_SCHEMA,
    });
    expect(noBackupForwardDeploymentSchemaBoundary(
      NO_BACKUP_TARGET_SCHEMA,
      NO_BACKUP_TARGET_SCHEMA,
    )).toEqual({
      sourceSchema: NO_BACKUP_TARGET_SCHEMA,
      targetSchema: NO_BACKUP_TARGET_SCHEMA,
    });
    expect(() => noBackupForwardDeploymentSchemaBoundary(
      NO_BACKUP_SOURCE_SCHEMA + 1,
      NO_BACKUP_TARGET_SCHEMA,
    )).toThrow("requires the canonical database");
    expect(() => noBackupForwardDeploymentSchemaBoundary(
      NO_BACKUP_TARGET_SCHEMA + 1,
      NO_BACKUP_TARGET_SCHEMA,
    )).toThrow("exact candidate ceiling");
  });

  test("keeps historical 60-to-ceiling receipts and current same-schema receipts recoverable", () => {
    const attestation = attestReleaseMigrationCeiling(process.cwd());
    expect(() => assertNoBackupForwardReceiptSchemaBoundary(
      NO_BACKUP_SOURCE_SCHEMA,
      NO_BACKUP_TARGET_SCHEMA,
      attestation,
    )).not.toThrow();
    expect(attestedNoBackupForwardSchemas(
      attestation,
      NO_BACKUP_SOURCE_SCHEMA,
      NO_BACKUP_TARGET_SCHEMA,
    )).toEqual(Array.from(
      { length: NO_BACKUP_TARGET_SCHEMA - NO_BACKUP_SOURCE_SCHEMA },
      (_, index) => NO_BACKUP_SOURCE_SCHEMA + index + 1,
    ));

    expect(() => assertNoBackupForwardReceiptSchemaBoundary(
      NO_BACKUP_TARGET_SCHEMA,
      NO_BACKUP_TARGET_SCHEMA,
      attestation,
    )).not.toThrow();
    expect(attestedNoBackupForwardSchemas(
      attestation,
      NO_BACKUP_TARGET_SCHEMA,
      NO_BACKUP_TARGET_SCHEMA,
    )).toEqual([]);
    expect(() => assertNoBackupForwardReceiptSchemaBoundary(
      NO_BACKUP_SOURCE_SCHEMA - 1,
      NO_BACKUP_TARGET_SCHEMA,
      attestation,
    )).toThrow("invalid database boundary");
    expect(() => assertNoBackupForwardReceiptSchemaBoundary(
      NO_BACKUP_SOURCE_SCHEMA + 1,
      NO_BACKUP_TARGET_SCHEMA,
      attestation,
    )).toThrow("invalid database boundary");
  });

  test("cleanly deploys a same-schema target in deterministic phase order", async () => {
    const calls: string[] = [];
    let targetCommitted = false;
    await expect(executeNoBackupForwardOnlyController({
      command: "deploy",
      sourceSchema: 60,
      targetSchema: 60,
      forwardSchemas: [],
      operations: {
        stop: () => {
          calls.push("stop");
        },
        withMaintenance: async (operation) => {
          calls.push("maintenance:enter");
          const result = await operation();
          calls.push("maintenance:exit");
          return result;
        },
        migrate: () => {
          calls.push("migration:no-op");
        },
        commitTarget: () => {
          calls.push("target:commit");
          targetCommitted = true;
        },
        startAndFinalize: (forceRecovery) => {
          calls.push(`start:${String(forceRecovery)}`);
        },
        observedSchema: () => 60,
        durableTargetCommitted: () => targetCommitted,
        restoreSourceBeforeSchemaCommit: () => {
          calls.push("restore");
        },
        ensureTargetCommitted: () => {
          calls.push("ensure_target");
        },
      },
    })).resolves.toEqual({
      status: "deployed",
      recoveryDirection: null,
      recovered: false,
    });
    expect(calls).toEqual([
      "stop",
      "maintenance:enter",
      "migration:no-op",
      "target:commit",
      "maintenance:exit",
      "start:false",
    ]);
  });

  test("same-schema failure restores source before durable target commitment", async () => {
    const calls: string[] = [];
    await expect(executeNoBackupForwardOnlyController({
      command: "deploy",
      sourceSchema: 60,
      targetSchema: 60,
      forwardSchemas: [],
      rethrowRestoredDeployFailure: false,
      operations: {
        stop: () => {
          calls.push("stop");
        },
        withMaintenance: async (operation) => operation(),
        migrate: () => {
          calls.push("migration:no-op");
        },
        commitTarget: () => {
          calls.push("target:failed-before-commit");
          throw new Error("injected pre-commit failure");
        },
        startAndFinalize: () => {
          calls.push("start");
        },
        observedSchema: () => 60,
        durableTargetCommitted: () => false,
        restoreSourceBeforeSchemaCommit: () => {
          calls.push("restore");
        },
        ensureTargetCommitted: () => {
          calls.push("ensure_target");
        },
      },
    })).resolves.toEqual({
      status: "predeploy_restored",
      recoveryDirection: "restore_source",
      recovered: true,
    });
    expect(calls).toEqual([
      "stop",
      "migration:no-op",
      "target:failed-before-commit",
      "restore",
    ]);
  });

  test("same-schema failure completes target after durable target commitment", async () => {
    const calls: string[] = [];
    let targetCommitted = false;
    await expect(executeNoBackupForwardOnlyController({
      command: "deploy",
      sourceSchema: 60,
      targetSchema: 60,
      forwardSchemas: [],
      operations: {
        stop: () => {
          calls.push("stop");
        },
        withMaintenance: async (operation) => operation(),
        migrate: () => {
          calls.push("migration:no-op");
        },
        commitTarget: () => {
          calls.push("target:committed");
          targetCommitted = true;
          throw new Error("injected post-commit failure");
        },
        startAndFinalize: (forceRecovery) => {
          calls.push(`start:${String(forceRecovery)}`);
        },
        observedSchema: () => 60,
        durableTargetCommitted: () => targetCommitted,
        restoreSourceBeforeSchemaCommit: () => {
          calls.push("restore");
        },
        ensureTargetCommitted: () => {
          calls.push("ensure_target");
        },
      },
    })).resolves.toEqual({
      status: "deployed",
      recoveryDirection: "complete_target",
      recovered: true,
    });
    expect(calls).toEqual([
      "stop",
      "migration:no-op",
      "target:committed",
      "ensure_target",
      "start:true",
    ]);
  });

  test("same-schema recovery applies cancellation only before target commitment", async () => {
    const sourceCalls: string[] = [];
    await expect(executeNoBackupForwardOnlyController({
      command: "recover",
      sourceSchema: 60,
      targetSchema: 60,
      forwardSchemas: [],
      recoveryInterruption: {
        throwIfAborted: () => {
          sourceCalls.push("abort_checked");
          throw new Error("cancelled before target commitment");
        },
      },
      operations: {
        stop: () => {
          sourceCalls.push("stop");
        },
        withMaintenance: async (operation) => operation(),
        migrate: () => {
          sourceCalls.push("migrate");
        },
        commitTarget: () => {
          sourceCalls.push("commit");
        },
        startAndFinalize: () => {
          sourceCalls.push("start");
        },
        observedSchema: () => 60,
        durableTargetCommitted: () => false,
        restoreSourceBeforeSchemaCommit: () => {
          sourceCalls.push("restore");
        },
        ensureTargetCommitted: () => {
          sourceCalls.push("ensure_target");
        },
      },
    })).rejects.toThrow("cancelled before target commitment");
    expect(sourceCalls).toEqual(["abort_checked"]);

    const targetCalls: string[] = [];
    await expect(executeNoBackupForwardOnlyController({
      command: "recover",
      sourceSchema: 60,
      targetSchema: 60,
      forwardSchemas: [],
      recoveryInterruption: {
        throwIfAborted: () => {
          targetCalls.push("unexpected_abort_check");
          throw new Error("must be ignored after target commitment");
        },
      },
      operations: {
        stop: () => {
          targetCalls.push("stop");
        },
        withMaintenance: async (operation) => operation(),
        migrate: () => {
          targetCalls.push("migrate");
        },
        commitTarget: () => {
          targetCalls.push("commit");
        },
        startAndFinalize: (forceRecovery) => {
          targetCalls.push(`start:${String(forceRecovery)}`);
        },
        observedSchema: () => 60,
        durableTargetCommitted: () => true,
        restoreSourceBeforeSchemaCommit: () => {
          targetCalls.push("restore");
        },
        ensureTargetCommitted: () => {
          targetCalls.push("ensure_target");
        },
      },
    })).resolves.toMatchObject({
      status: "deployed",
      recoveryDirection: "complete_target",
      recovered: true,
    });
    expect(targetCalls).toEqual(["ensure_target", "start:true"]);
  });

  test("cancellation aborts source recovery before mutation but cannot interrupt target completion", async () => {
    const sourceCalls: string[] = [];
    await expect(executeNoBackupForwardOnlyController({
      command: "recover",
      sourceSchema: 47,
      targetSchema: 60,
      forwardSchemas: Array.from(
        { length: 13 },
        (_, index) => index + 48,
      ),
      recoveryInterruption: {
        throwIfAborted: () => {
          sourceCalls.push("abort_checked");
          throw new Error("cancelled before source recovery");
        },
      },
      operations: {
        stop: () => { sourceCalls.push("stop"); },
        withMaintenance: async (operation) => operation(),
        migrate: () => { sourceCalls.push("migrate"); },
        commitTarget: () => { sourceCalls.push("commit"); },
        startAndFinalize: () => { sourceCalls.push("start"); },
        observedSchema: () => 47,
        restoreSourceBeforeSchemaCommit: () => {
          sourceCalls.push("restore");
        },
        ensureTargetCommitted: () => {
          sourceCalls.push("ensure_target");
        },
      },
    })).rejects.toThrow("cancelled before source recovery");
    expect(sourceCalls).toEqual(["abort_checked"]);

    const targetCalls: string[] = [];
    await expect(executeNoBackupForwardOnlyController({
      command: "recover",
      sourceSchema: 47,
      targetSchema: 60,
      forwardSchemas: Array.from(
        { length: 13 },
        (_, index) => index + 48,
      ),
      recoveryInterruption: {
        throwIfAborted: () => {
          throw new Error("must be ignored after schema commit");
        },
      },
      operations: {
        stop: () => { targetCalls.push("stop"); },
        withMaintenance: async (operation) => operation(),
        migrate: () => { targetCalls.push("migrate"); },
        commitTarget: () => { targetCalls.push("commit"); },
        startAndFinalize: (forceRecovery) => {
          targetCalls.push(`start:${String(forceRecovery)}`);
        },
        observedSchema: () => 53,
        restoreSourceBeforeSchemaCommit: () => {
          targetCalls.push("restore");
        },
        ensureTargetCommitted: () => {
          targetCalls.push("ensure_target");
        },
      },
    })).resolves.toMatchObject({
      status: "deployed",
      recoveryDirection: "complete_target",
      recovered: true,
    });
    expect(targetCalls).toEqual(["ensure_target", "start:true"]);
  });

  test("requires running-state proof and permits one post-start runtime reactivation", () => {
    const root = temporaryDirectory("ti-scale-no-backup-running-proof-");
    const receiptPath = join(root, "receipt.json");
    writeFileSync(receiptPath, "{}\n");
    const journal = join(root, "transaction-journal");
    createFunctionalReleaseTransactionJournal({
      directory: journal,
      operation: "deploy",
      releaseId: "no-backup-running-proof",
      receiptPath,
      recoveryIntent: "restore_predeploy",
      identity: {
        deploymentKind: "no_backup_preview_v1",
        requireRunningStateVerification: true,
        targetRuntimeCommitProtocol: RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL,
        predeploy: { databaseSchema: 47 },
        target: { databaseSchema: 48 },
      },
      transactionId: "no-backup-running-proof-transaction",
    });
    for (const mutation of [
      "service_stop",
      "database_migration",
      "application_activation",
      "static_activation",
      "target_data_verification",
    ]) {
      prepareFunctionalReleaseMutation(journal, "forward", mutation);
      completeFunctionalReleaseMutation(journal, "forward", mutation);
    }
    commitFunctionalReleaseTransactionTarget(journal, {
      databaseSchema: 48,
      pointers: { application: "target", static: "target" },
    });
    appendFunctionalReleaseTransactionRecord(journal, {
      event: "recovery_started",
      detail: { recoveryIntent: "complete_target" },
    });
    prepareFunctionalReleaseMutation(journal, "recovery", "service_start");
    completeFunctionalReleaseMutation(journal, "recovery", "service_start");
    const committedLegacy = {
      activeState: "active",
      mainPid: 3132,
      invocationId: "e".repeat(32),
      healthStatus: 200,
      semanticStatus: "healthy",
    };
    const committedReceipt = {
      status: "deployed",
      chillspwnAfter: committedLegacy,
    };
    const committedReceiptSha256 = createHash("sha256").update(
      `${JSON.stringify(
        JSON.parse(canonicalReleaseTransactionJson(committedReceipt)),
        null,
        2,
      )}\n`,
    ).digest("hex");
    const committedLegacySha256 =
      releaseTransactionSha256(committedLegacy);
    expect(() => prepareFunctionalReleaseMutation(
      journal,
      "recovery",
      "deployment_receipt_commit",
    )).toThrow("immutable prepared intent");
    prepareFunctionalReleaseMutation(
      journal,
      "recovery",
      "deployment_receipt_commit",
      {
        receiptPath,
        receipt: committedReceipt,
        receiptSha256: committedReceiptSha256,
        legacyIdentitySha256: committedLegacySha256,
      },
    );
    completeFunctionalReleaseMutation(
      journal,
      "recovery",
      "deployment_receipt_commit",
      {
        receiptPath,
        receiptSha256: committedReceiptSha256,
        legacyIdentitySha256: committedLegacySha256,
      },
    );

    expect(() => appendFunctionalReleaseTransactionRecord(journal, {
      event: "terminal",
      detail: {
        outcome: "deployed",
        receiptPath,
        receiptSha256: committedReceiptSha256,
        legacyIdentitySha256: committedLegacySha256,
        receiptLegacyIdentitySha256: committedLegacySha256,
        reconciliationLegacyIdentitySha256: committedLegacySha256,
      },
    })).toThrow("durable running-state verification");

    const targetState = { databaseSchema: 48 };
    prepareFunctionalReleaseMutation(
      journal,
      "recovery",
      "running_state_verification",
      { targetState },
    );
    const targetStateSha256 = createHash("sha256").update(
      JSON.stringify(targetState),
    ).digest("hex");
    completeFunctionalReleaseMutation(
      journal,
      "recovery",
      "running_state_verification",
      {
        outcome: "already_exact",
        invocationId: "a".repeat(32),
        targetState,
        targetStateSha256,
      },
    );
    expect(assertReleaseServiceStartAdmitted({
      transactionRoot: root,
      releaseLockPath: join(root, "release.lock"),
      authorizationPath: join(root, "start-authorization.json"),
      startupMutationBarrierPath: join(root, "startup-barrier"),
      invocationId: "b".repeat(32),
    })).toEqual({
      mode: "target_runtime_committed",
      transactionId: "no-backup-running-proof-transaction",
    });
    appendFunctionalReleaseTransactionRecord(journal, {
      event: "terminal",
      detail: {
        outcome: "deployed",
        receiptPath,
        receiptSha256: committedReceiptSha256,
        legacyIdentitySha256: committedLegacySha256,
        receiptLegacyIdentitySha256: committedLegacySha256,
        reconciliationLegacyIdentitySha256: committedLegacySha256,
      },
    });
    expect(readFunctionalReleaseTransactionJournal(journal).terminal?.detail?.outcome)
      .toBe("deployed");
  });

  test("a restarted recovery direct-starts an already committed forward runtime without a token", async () => {
    const root = temporaryDirectory("ti-scale-no-backup-forward-crash-recovery-");
    const receiptPath = join(root, "receipt.json");
    writeFileSync(receiptPath, "{}\n");
    const journal = join(root, "transaction-journal");
    const targetState = {
      pointers: { applicationTarget: "/opt/target", staticReleaseId: "target" },
      databaseSchema: 48,
    };
    createFunctionalReleaseTransactionJournal({
      directory: journal,
      operation: "deploy",
      releaseId: "no-backup-forward-crash-recovery",
      receiptPath,
      recoveryIntent: "restore_predeploy",
      identity: {
        targetRuntimeCommitProtocol: RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL,
        predeploy: { databaseSchema: 47 },
        target: targetState,
      },
      transactionId: "no-backup-forward-crash-recovery-transaction",
    });
    for (const mutation of [
      "service_stop",
      "database_migration",
      "application_activation",
      "static_activation",
      "target_data_verification",
    ]) {
      prepareFunctionalReleaseMutation(journal, "forward", mutation);
      completeFunctionalReleaseMutation(journal, "forward", mutation);
    }
    commitFunctionalReleaseTransactionTarget(journal, targetState);
    prepareFunctionalReleaseMutation(journal, "forward", "service_start");
    completeFunctionalReleaseMutation(journal, "forward", "service_start");
    prepareFunctionalReleaseMutation(
      journal,
      "forward",
      "running_state_verification",
      {
        targetState,
        targetStateSha256: releaseTransactionSha256(targetState),
      },
    );
    completeFunctionalReleaseMutation(
      journal,
      "forward",
      "running_state_verification",
      {
        outcome: "already_exact",
        invocationId: "1".repeat(32),
        targetState,
        targetStateSha256: releaseTransactionSha256(targetState),
      },
    );

    // Simulate controller death before receipt/terminal, then a fresh
    // reconciliation process preparing recovery activation while the service
    // is inactive.
    appendFunctionalReleaseTransactionRecord(journal, {
      event: "recovery_started",
      detail: { recoveryIntent: "complete_target" },
    });
    prepareFunctionalReleaseMutation(journal, "recovery", "service_start");
    expect(noBackupTargetStartMode(
      readFunctionalReleaseTransactionJournal(journal),
    )).toBe("target_runtime_committed");

    const worker = Bun.spawn([
      process.execPath,
      join(
        process.cwd(),
        "tests/unit/release/fixtures/no-backup-target-start-mode-worker.ts",
      ),
      journal,
    ], {
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(await worker.exited).toBe(0);
    expect((await new Response(worker.stdout).text()).trim())
      .toBe("target_runtime_committed");
    expect((await new Response(worker.stderr).text()).trim()).toBe("");
    expect(existsSync(join(root, "start-authorization.json"))).toBe(false);

    // A second crash after recovery service_start was completed but before its
    // running proof is also restartable without creating a conflicting token.
    completeFunctionalReleaseMutation(journal, "recovery", "service_start");
    prepareFunctionalReleaseMutation(
      journal,
      "recovery",
      "running_state_verification",
      {
        targetState,
        targetStateSha256: releaseTransactionSha256(targetState),
      },
    );
    expect(noBackupTargetStartMode(
      readFunctionalReleaseTransactionJournal(journal),
    )).toBe("target_runtime_committed");
    const secondWorker = Bun.spawn([
      process.execPath,
      join(
        process.cwd(),
        "tests/unit/release/fixtures/no-backup-target-start-mode-worker.ts",
      ),
      journal,
    ], {
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(await secondWorker.exited).toBe(0);
    expect((await new Response(secondWorker.stdout).text()).trim())
      .toBe("target_runtime_committed");
    expect((await new Response(secondWorker.stderr).text()).trim()).toBe("");
    expect(existsSync(join(root, "start-authorization.json"))).toBe(false);
  });

  test("migrates an exact schema-47 database to the canonical current schema without creating backup payloads", async () => {
    const root = temporaryDirectory("ti-scale-no-backup-current-schema-");
    const databasePath = join(root, "state", "ti-scale.sqlite");
    mkdirSync(join(root, "state"), { recursive: true });
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(
        database,
        DATABASE_MIGRATIONS.slice(0, 47).map(withoutBackupRequirement),
      );
    } finally {
      database.close();
    }
    expect(schemaVersion(databasePath)).toBe(47);

    const stdout = spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      expect(await runDatabaseCli([
        "migrate",
        "--db",
        databasePath,
        "--no-backup",
        "--acknowledge-no-backup-risk",
      ], {})).toBe(0);
    } finally {
      stdout.mockRestore();
    }

    expect(DATABASE_MIGRATIONS.at(-1)?.version).toBe(
      NO_BACKUP_TARGET_SCHEMA,
    );
    expect(schemaVersion(databasePath)).toBe(NO_BACKUP_TARGET_SCHEMA);
    expect(existsSync(join(root, "state", "backups"))).toBe(false);
    expect(existsSync(join(root, "state", "migration-backups"))).toBe(false);
  });

  test("rolls back a failed schema-48 transaction to the intact schema-47 state", () => {
    const root = temporaryDirectory("ti-scale-no-backup-schema48-failure-");
    const databasePath = join(root, "ti-scale.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      const source = DATABASE_MIGRATIONS.slice(0, 47).map(withoutBackupRequirement);
      migrateDatabase(database, source);
      const target = DATABASE_MIGRATIONS[47]!;
      const injectedFailure: Migration = {
        ...withoutBackupRequirement(target),
        name: `${target.name}_injected_failure`,
        sql: `${target.sql}\nTHIS IS NOT VALID SQL;`,
      };
      expect(() => migrateDatabase(database, [...source, injectedFailure]))
        .toThrow();
      expect(Number((database.prepare(
        "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
      ).get() as { readonly version: number }).version)).toBe(47);
      const columns = database.prepare("PRAGMA table_info(provider_turns)").all() as Array<{
        readonly name: string;
      }>;
      expect(columns.some((column) => column.name === "agent_id")).toBe(false);
      expect(database.prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?",
      ).get("idx_provider_turns_agent_time")).toBeNull();
    } finally {
      database.close();
    }
    expect(existsSync(join(root, "backups"))).toBe(false);
    expect(existsSync(join(root, "migration-backups"))).toBe(false);
  });
});
