import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
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
  createNoBackupCandidateLifecycle,
  inspectNoBackupCandidateSource,
  parseNoBackupCandidateArguments,
  runNoBackupCandidateRelease,
  stageNoBackupCandidatePair,
  type NoBackupCandidateStagingInput,
} from "../../../scripts/release/NoBackupCandidateStaging";
import {
  stageServerRelease,
} from "../../../scripts/release/FunctionalReleasePrimitives";
import {
  captureNoBackupPayloadInventory,
  NO_BACKUP_PAYLOAD_ROOTS,
  type NoBackupPreviewReceipt,
} from "../../../scripts/release/NoBackupPreviewRelease";
import {
  StaticArtifactReleaseStore,
} from "../../../server/static-release";

const temporaryDirectories: string[] = [];

function temporaryDirectory(prefix: string): string {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

function command(args: readonly string[], cwd: string): string {
  const result = Bun.spawnSync([...args], {
    cwd,
    env: {
      PATH: "/usr/local/bin:/usr/bin:/bin",
      HOME: cwd,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
    },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(
      new TextDecoder().decode(result.stderr).trim() ||
        `Command failed: ${args.join(" ")}`,
    );
  }
  return new TextDecoder().decode(result.stdout).trim();
}

function writeServerSource(
  root: string,
  marker: string,
  withStatic = false,
): void {
  mkdirSync(join(root, "server"), { recursive: true });
  writeFileSync(
    join(root, "package.json"),
    `${JSON.stringify({
      name: `ti-scale-${marker}`,
      private: true,
    }, null, 2)}\n`,
  );
  writeFileSync(
    join(root, "server", "index.ts"),
    `export const release = ${JSON.stringify(marker)};\n`,
  );
  if (withStatic) {
    mkdirSync(join(root, "dist"), { recursive: true });
    writeFileSync(
      join(root, "dist", "index.html"),
      `<main>${marker}</main>\n`,
    );
    writeFileSync(
      join(root, "dist", "app.js"),
      `export const release = ${JSON.stringify(marker)};\n`,
    );
  }
}

function initializeGitSource(root: string): string {
  command(["/usr/bin/git", "init", "--quiet"], root);
  command(
    ["/usr/bin/git", "config", "user.email", "release@test.invalid"],
    root,
  );
  command(
    ["/usr/bin/git", "config", "user.name", "Release Test"],
    root,
  );
  command(["/usr/bin/git", "add", "--all"], root);
  command(
    ["/usr/bin/git", "commit", "--quiet", "-m", "pinned source"],
    root,
  );
  return command(
    ["/usr/bin/git", "rev-parse", "--verify", "HEAD^{commit}"],
    root,
  );
}

async function candidateFixture() {
  const root = temporaryDirectory(
    "ti-scale-no-backup-candidate-staging-",
  );
  const sourceRoot = join(root, "ti-scale-source");
  const activeServerSource = join(root, "active-ti-scale-source");
  const activeStaticSource = join(root, "active-ti-scale-static");
  const serverReleaseRoot = join(root, "ti-scale-server-releases");
  const staticReleaseRoot = join(root, "ti-scale-static-releases");
  const applicationPath = join(root, "ti-scale-active");
  mkdirSync(sourceRoot);
  mkdirSync(activeServerSource);
  mkdirSync(activeStaticSource);
  writeServerSource(sourceRoot, "candidate", true);
  writeServerSource(activeServerSource, "active");
  writeFileSync(
    join(activeStaticSource, "index.html"),
    "<main>active</main>\n",
  );
  const sourceCommit = initializeGitSource(sourceRoot);

  const activeServer = await stageServerRelease({
    sourceRoot: activeServerSource,
    releaseRoot: serverReleaseRoot,
    releaseId: "active-release",
  });
  symlinkSync(activeServer.releaseDirectory, applicationPath);
  const staticStore = new StaticArtifactReleaseStore({
    releaseRoot: staticReleaseRoot,
  });
  const activeStatic = staticStore.stageRelease({
    releaseId: "active-release",
    sourceDirectory: activeStaticSource,
  });
  staticStore.activateRelease(activeStatic.releaseId);
  const inspection = await inspectNoBackupCandidateSource({
    sourceRoot,
    staticBuildRoot: join(sourceRoot, "dist"),
  });
  expect(inspection.sourceCommit).toBe(sourceCommit);

  const input: NoBackupCandidateStagingInput = {
    releaseId: "candidate-release",
    sourceRoot,
    staticBuildRoot: join(sourceRoot, "dist"),
    sourceCommit,
    sourceTreeSha256: inspection.sourceTreeSha256,
    staticArtifactSha256: inspection.staticArtifactSha256,
    serverReleaseRoot,
    staticReleaseRoot,
    applicationPath,
  };
  return {
    root,
    input,
    inspection,
    sourceRoot,
    serverReleaseRoot,
    staticReleaseRoot,
    applicationPath,
    staticStore,
    activeServer,
    activeStatic,
  };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("forward-only no-backup candidate staging", () => {
  test("inspects only an exact clean Git root and binds its exact dist tree", async () => {
    const fixture = await candidateFixture();
    expect(fixture.inspection).toMatchObject({
      schemaVersion:
        "ti-scale.no-backup-candidate-source-inspection.v1",
      sourceRoot: fixture.sourceRoot,
      staticBuildRoot: join(fixture.sourceRoot, "dist"),
      sourceCommit: fixture.input.sourceCommit,
      sourceTreeSha256: fixture.input.sourceTreeSha256,
      staticArtifactSha256:
        fixture.input.staticArtifactSha256,
      gitStatus: "clean",
    });
    expect(fixture.inspection.sourceEntryCount).toBeGreaterThan(2);
    expect(fixture.inspection.staticEntryCount).toBe(2);
    await expect(inspectNoBackupCandidateSource({
      sourceRoot: join(fixture.sourceRoot, "server"),
      staticBuildRoot: join(fixture.sourceRoot, "dist"),
    })).rejects.toThrow("exact dist directory");
  });

  test("stages a same-ID manifest-bound pair without moving either active pointer", async () => {
    const fixture = await candidateFixture();
    const beforePointer = fixture.staticStore.readActivePointer();
    const staged = await stageNoBackupCandidatePair(fixture.input);
    expect(staged.createdServerRelease).toBe(true);
    expect(staged.createdStaticRelease).toBe(true);
    expect(staged.binding).toMatchObject({
      schemaVersion:
        "ti-scale.no-backup-candidate-staging-binding.v1",
      releaseId: "candidate-release",
      sourceCommit: fixture.input.sourceCommit,
      sourceTreeSha256: fixture.input.sourceTreeSha256,
      staticArtifactSha256:
        fixture.input.staticArtifactSha256,
      serverRelease: {
        treeSha256: fixture.input.sourceTreeSha256,
      },
      staticRelease: {
        artifactSha256: fixture.input.staticArtifactSha256,
      },
    });
    expect(fixture.staticStore.readActivePointer()).toEqual(
      beforePointer,
    );
    expect(existsSync(fixture.activeServer.releaseDirectory)).toBe(
      true,
    );
    expect(captureNoBackupPayloadInventory(NO_BACKUP_PAYLOAD_ROOTS).entries)
      .toEqual([]);
  });

  test("is idempotent only when both immutable candidates still match every pin", async () => {
    const fixture = await candidateFixture();
    const first = await stageNoBackupCandidatePair(fixture.input);
    const second = await stageNoBackupCandidatePair(fixture.input);
    expect(second.binding).toEqual(first.binding);
    expect(second.createdServerRelease).toBe(false);
    expect(second.createdStaticRelease).toBe(false);

    const candidateIndex = join(
      fixture.staticReleaseRoot,
      "releases",
      fixture.input.releaseId,
      "index.html",
    );
    chmodSync(candidateIndex, 0o644);
    writeFileSync(candidateIndex, "<main>tampered</main>\n");
    await expect(stageNoBackupCandidatePair(fixture.input))
      .rejects.toThrow(/tampered|incomplete|manifest/u);
    expect(existsSync(fixture.activeServer.releaseDirectory)).toBe(
      true,
    );
  });

  test("fails closed for dirty, missing, or mismatched pins before staging", async () => {
    expect(() => parseNoBackupCandidateArguments([
      "stage-deploy",
      "--source-root",
      "/tmp/clean",
      "--static-build-root",
      "/tmp/clean/dist",
      "--release-id",
      "candidate",
      "--confirm",
      "candidate",
      "--execute",
      "--acknowledge-no-backup-risk",
    ])).toThrow("--source-commit");

    const dirty = await candidateFixture();
    writeFileSync(
      join(dirty.sourceRoot, "server", "index.ts"),
      "export const dirty = true;\n",
    );
    await expect(stageNoBackupCandidatePair(dirty.input))
      .rejects.toThrow("clean Git worktree");
    expect(existsSync(join(
      dirty.serverReleaseRoot,
      "releases",
      dirty.input.releaseId,
    ))).toBe(false);

    const mismatched = await candidateFixture();
    await expect(stageNoBackupCandidatePair({
      ...mismatched.input,
      sourceTreeSha256: "0".repeat(64),
    })).rejects.toThrow("Pinned server source tree SHA-256");
    expect(existsSync(join(
      mismatched.staticReleaseRoot,
      "releases",
      mismatched.input.releaseId,
    ))).toBe(false);
  });

  test("removes only the half it created when the other half fails validation", async () => {
    const fixture = await candidateFixture();
    const wrongStatic = join(
      fixture.root,
      "wrong-ti-scale-static",
    );
    mkdirSync(wrongStatic);
    writeFileSync(
      join(wrongStatic, "index.html"),
      "<main>wrong immutable candidate</main>\n",
    );
    fixture.staticStore.stageRelease({
      releaseId: fixture.input.releaseId,
      sourceDirectory: wrongStatic,
    });

    await expect(stageNoBackupCandidatePair(fixture.input))
      .rejects.toThrow(
        "Existing static candidate differs from the pinned browser build",
      );
    expect(existsSync(join(
      fixture.serverReleaseRoot,
      "releases",
      fixture.input.releaseId,
    ))).toBe(false);
    expect(existsSync(join(
      fixture.staticReleaseRoot,
      "releases",
      fixture.input.releaseId,
    ))).toBe(true);
    expect(existsSync(fixture.activeServer.releaseDirectory)).toBe(
      true,
    );
    expect(fixture.staticStore.readActivePointer()).toMatchObject({
      activeReleaseId: fixture.activeStatic.releaseId,
    });
  });

  test("uses the canonical complete nine-root no-backup inventory", () => {
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
  });

  test("hands the bound lifecycle to the existing controller contract and cleans a pre-transaction refusal", async () => {
    const fixture = await candidateFixture();
    const fakeReceipt = {
      schemaVersion: "ti-scale.no-backup-preview-release-receipt.v1",
      releaseId: fixture.input.releaseId,
      status: "failed_predeploy_restored",
      backupPolicy: "none",
      cutoverEligible: false,
      rollbackCapability: "none_after_schema_commit",
    } as unknown as NoBackupPreviewReceipt;
    let handoffCount = 0;
    const result = await runNoBackupCandidateRelease([
      "stage-deploy",
      "--source-root",
      fixture.sourceRoot,
      "--static-build-root",
      join(fixture.sourceRoot, "dist"),
      "--source-commit",
      fixture.input.sourceCommit,
      "--source-tree-sha256",
      fixture.input.sourceTreeSha256,
      "--static-artifact-sha256",
      fixture.input.staticArtifactSha256,
      "--release-id",
      fixture.input.releaseId,
      "--confirm",
      fixture.input.releaseId,
      "--execute",
      "--acknowledge-no-backup-risk",
    ], {
      serverReleaseRoot: fixture.serverReleaseRoot,
      staticReleaseRoot: fixture.staticReleaseRoot,
      applicationPath: fixture.applicationPath,
      runRelease: async (argv, lifecycle) => {
        handoffCount += 1;
        expect(argv).toEqual([
          "deploy",
          "--execute",
          "--release-id",
          fixture.input.releaseId,
          "--confirm",
          fixture.input.releaseId,
          "--acknowledge-no-backup-risk",
        ]);
        const candidate = await lifecycle.stage();
        expect(candidate.releaseId).toBe(fixture.input.releaseId);
        await lifecycle.discardBeforeTransaction(candidate);
        return fakeReceipt;
      },
    });
    expect(result).toEqual({
      command: "stage-deploy",
      receipt: fakeReceipt,
    });
    expect(handoffCount).toBe(1);
    expect(existsSync(join(
      fixture.serverReleaseRoot,
      "releases",
      fixture.input.releaseId,
    ))).toBe(false);
    expect(existsSync(join(
      fixture.staticReleaseRoot,
      "releases",
      fixture.input.releaseId,
    ))).toBe(false);
  });

  test("the lifecycle never deletes a pre-existing idempotent pair", async () => {
    const fixture = await candidateFixture();
    await stageNoBackupCandidatePair(fixture.input);
    const lifecycle = createNoBackupCandidateLifecycle(fixture.input);
    const candidate = await lifecycle.stage();
    await lifecycle.discardBeforeTransaction(candidate);
    expect(existsSync(candidate.serverRelease.path)).toBe(true);
    expect(existsSync(candidate.staticRelease.path)).toBe(true);
  });

  test("package exposure contains no legacy backup or direct static mutation handoff", () => {
    const packageJson = JSON.parse(
      readFileSync(join(process.cwd(), "package.json"), "utf8"),
    ) as { readonly scripts: Record<string, string> };
    expect(packageJson.scripts[
      "release:no-backup:inspect-candidate"
    ]).toContain("no-backup-candidate-release.ts inspect");
    expect(packageJson.scripts[
      "release:no-backup:stage-deploy"
    ]).toContain("no-backup-candidate-release.ts stage-deploy");
    expect(packageJson.scripts[
      "release:no-backup:stage-deploy"
    ]).not.toMatch(
      /functional-release|backup-prune|rollback|archive|snapshot/u,
    );
    expect(packageJson.scripts["release:no-backup:recover"])
      .toContain("no-backup-preview-release.ts recover");
  });
});
