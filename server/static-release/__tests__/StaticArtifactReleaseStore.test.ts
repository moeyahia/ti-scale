import { afterEach, describe, expect, spyOn, test } from "bun:test";
import * as nodeFs from "node:fs";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { runStaticReleaseCli } from "../cli";
import {
  finalizeSupersededReleaseArtifacts,
} from "../../../scripts/release/NoBackupPreviewRelease";
import {
  STATIC_RELEASE_POINTER,
  StaticArtifactReleaseStore,
  StaticReleaseError,
} from "../StaticArtifactReleaseStore";

const roots: string[] = [];
const NOW = "2026-07-17T05:30:00.000Z";

function makeWritable(path: string): void {
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch {
    return;
  }
  if (metadata.isSymbolicLink()) return;
  if (metadata.isDirectory()) {
    chmodSync(path, 0o700);
    for (const name of readdirSync(path)) makeWritable(join(path, name));
    return;
  }
  chmodSync(path, 0o600);
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    makeWritable(root);
    rmSync(root, { recursive: true, force: true });
  }
});

function fixture() {
  const workspace = mkdtempSync(join(tmpdir(), "ti-scale-static-release-test-"));
  roots.push(workspace);
  const sourceDirectory = join(workspace, "ti-scale-dist");
  const releaseRoot = join(workspace, "ti-scale-release-root");
  mkdirSync(join(sourceDirectory, "assets"), { recursive: true });
  writeFileSync(join(sourceDirectory, "index.html"), "<!doctype html><title>release one</title>\n");
  writeFileSync(join(sourceDirectory, "assets", "app.js"), "globalThis.release = 'one';\n");
  const store = new StaticArtifactReleaseStore({
    releaseRoot,
    clock: () => new Date(NOW),
  });
  return { workspace, sourceDirectory, releaseRoot, store };
}

function expectStaticError(operation: () => unknown, code: StaticReleaseError["code"]): void {
  try {
    operation();
    throw new Error("Expected StaticReleaseError");
  } catch (error) {
    expect(error).toBeInstanceOf(StaticReleaseError);
    expect((error as StaticReleaseError).code).toBe(code);
  }
}

describe("immutable V2 static artifact handoff", () => {
  test("durably publishes a first-use layout and every nested staged directory bottom-up", () => {
    const { workspace, sourceDirectory, releaseRoot, store } = fixture();
    mkdirSync(join(sourceDirectory, "assets", "chunks", "leaf"), { recursive: true });
    writeFileSync(join(sourceDirectory, "assets", "chunks", "leaf", "chunk.js"), "export const durable = true;\n");

    const operations: Array<{ readonly kind: "file" | "directory"; readonly path: string }> = [];
    const realFsyncSync = nodeFs.fsyncSync;
    const fsync = spyOn(nodeFs, "fsyncSync").mockImplementation((descriptor: number) => {
      const metadata = nodeFs.fstatSync(descriptor);
      operations.push({
        kind: metadata.isFile() ? "file" : "directory",
        path: nodeFs.readlinkSync(`/proc/self/fd/${descriptor}`),
      });
      realFsyncSync(descriptor);
    });
    let staged: ReturnType<StaticArtifactReleaseStore["stageRelease"]>;
    try {
      staged = store.stageRelease({ releaseId: "release-durable", sourceDirectory });
    } finally { fsync.mockRestore(); }

    const firstIndex = (path: string): number => operations.findIndex(
      (operation) => operation.kind === "directory" && operation.path === path,
    );
    const releasesDirectory = join(releaseRoot, "releases");
    const stateDirectory = join(releaseRoot, "state");
    expect(firstIndex(releaseRoot)).toBeGreaterThanOrEqual(0);
    expect(firstIndex(workspace)).toBeGreaterThan(firstIndex(releaseRoot));
    expect(firstIndex(releasesDirectory)).toBeGreaterThan(firstIndex(workspace));
    expect(firstIndex(stateDirectory)).toBeGreaterThan(firstIndex(releasesDirectory));

    const stagingRoot = operations.find((operation) =>
      operation.kind === "directory" && dirname(operation.path) === releasesDirectory &&
      basename(operation.path).startsWith(".stage-release-durable-"))?.path;
    expect(stagingRoot).toBeDefined();
    const stagedLeaf = join(stagingRoot!, "assets", "chunks", "leaf");
    const stagedChunks = dirname(stagedLeaf);
    const stagedAssets = dirname(stagedChunks);
    const directoryIndex = (path: string): number => operations.findIndex(
      (operation) => operation.kind === "directory" && operation.path === path,
    );
    expect(directoryIndex(stagedLeaf)).toBeGreaterThanOrEqual(0);
    expect(directoryIndex(stagedChunks)).toBeGreaterThan(directoryIndex(stagedLeaf));
    expect(directoryIndex(stagedAssets)).toBeGreaterThan(directoryIndex(stagedChunks));
    expect(directoryIndex(stagingRoot!)).toBeGreaterThan(directoryIndex(stagedAssets));
    expect(operations.some(
      (operation) => operation.kind === "file" && operation.path.endsWith("/assets/chunks/leaf/chunk.js"),
    )).toBe(true);
    expect(staged.releaseDirectory).toBe(join(releasesDirectory, "release-durable"));
  });

  test("fails closed when first-use layout or nested-directory durability cannot be established", () => {
    for (const target of ["layout-parent", "nested-directory"] as const) {
      const { workspace, sourceDirectory, releaseRoot, store } = fixture();
      mkdirSync(join(sourceDirectory, "assets", "chunks"), { recursive: true });
      writeFileSync(join(sourceDirectory, "assets", "chunks", "chunk.js"), "export {};\n");
      const releaseId = `release-fsync-${target}`;
      const releasesDirectory = join(releaseRoot, "releases");
      const destination = join(releasesDirectory, releaseId);
      const realFsyncSync = nodeFs.fsyncSync;
      let injected = false;
      const fsync = spyOn(nodeFs, "fsyncSync").mockImplementation((descriptor: number) => {
        const metadata = nodeFs.fstatSync(descriptor);
        const path = nodeFs.readlinkSync(`/proc/self/fd/${descriptor}`);
        const matches = target === "layout-parent"
          ? metadata.isDirectory() && path === workspace
          : metadata.isDirectory() && path.endsWith("/assets/chunks") &&
            path.includes(`/.stage-${releaseId}-`);
        if (matches) {
          injected = true;
          throw Object.assign(new Error(`simulated ${target} fsync failure`), { code: "EIO" });
        }
        realFsyncSync(descriptor);
      });
      try {
        expect(() => store.stageRelease({ releaseId, sourceDirectory })).toThrow(
          `simulated ${target} fsync failure`,
        );
      } finally { fsync.mockRestore(); }

      expect(injected).toBe(true);
      expect(existsSync(destination)).toBe(false);
      if (existsSync(releasesDirectory)) {
        expect(readdirSync(releasesDirectory).some((name) => name.startsWith(`.stage-${releaseId}-`))).toBe(false);
      }
    }
  });

  test("stages through an atomic version directory, verifies every file, and pins an exact release", () => {
    const { sourceDirectory, releaseRoot, store } = fixture();
    const staged = store.stageRelease({ releaseId: "release-001", sourceDirectory });

    expect(staged.releaseDirectory).toBe(join(releaseRoot, "releases", "release-001"));
    expect(staged.manifest.entries.map((entry) => entry.path)).toEqual(["assets/app.js", "index.html"]);
    expect(staged.manifestSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(readdirSync(join(releaseRoot, "releases"))).toEqual(["release-001"]);
    expect(store.verifyRelease("release-001", staged.manifestSha256)).toEqual(staged);

    const activated = store.activateRelease("release-001");
    expect(activated.pointerGeneration).toBe(1);
    expect(store.readActivePointer()).toMatchObject({
      scope: "v2_static_artifact_pointer_only",
      activeReleaseId: "release-001",
      previousReleaseId: null,
    });
    const pinned = store.pinActiveRelease();
    expect(pinned.releaseDirectory).toBe(staged.releaseDirectory);
    expect(pinned.manifestSha256).toBe(staged.manifestSha256);
    expect(pinned.releaseDirectory).not.toContain("/state/");
  });

  test("pins the active immutable release without exposing a rollback operation", () => {
    const { sourceDirectory, releaseRoot, store } = fixture();
    store.stageRelease({ releaseId: "release-001", sourceDirectory });
    const first = store.activateRelease("release-001");
    const processPin = store.pinActiveRelease();

    writeFileSync(join(sourceDirectory, "index.html"), "<!doctype html><title>release two</title>\n");
    writeFileSync(join(sourceDirectory, "assets", "app.js"), "globalThis.release = 'two';\n");
    store.stageRelease({ releaseId: "release-002", sourceDirectory });
    const second = store.activateRelease("release-002");

    expect(second.pointerGeneration).toBe(2);
    expect(store.readActivePointer()).toMatchObject({
      activeReleaseId: "release-002",
      previousReleaseId: "release-001",
      previousManifestSha256: first.manifestSha256,
    });
    expect(readdirSync(join(releaseRoot, "releases")).sort()).toEqual(["release-001", "release-002"]);
    expect(processPin.releaseDirectory).toBe(join(releaseRoot, "releases", "release-001"));
    expect(readFileSync(join(processPin.releaseDirectory, "index.html"), "utf8")).toContain("release one");

    expect("rollbackPointer" in store).toBe(false);
    expect(store.pinActiveRelease()).toMatchObject({
      releaseId: "release-002",
      manifestSha256: second.manifestSha256,
      pointerGeneration: 2,
    });
  });

  test("clears prior identity before deletion and replays safely after a crash", () => {
    const { sourceDirectory, releaseRoot, store } = fixture();
    const first = store.stageRelease({
      releaseId: "release-001",
      sourceDirectory,
    });
    store.activateRelease("release-001");
    writeFileSync(
      join(sourceDirectory, "index.html"),
      "<!doctype html><title>release two</title>\n",
    );
    writeFileSync(
      join(sourceDirectory, "assets", "app.js"),
      "globalThis.release = 'two';\n",
    );
    const second = store.stageRelease({
      releaseId: "release-002",
      sourceDirectory,
    });
    store.activateRelease("release-002");

    expect(() => store.finalizeForwardOnlyActivation({
      activeReleaseId: second.releaseId,
      activeManifestSha256: second.manifestSha256,
      supersededReleaseId: first.releaseId,
      supersededManifestSha256: first.manifestSha256,
      onPreviousIdentityCleared: () => {
        throw new Error("simulated controller crash after pointer cleanup");
      },
    })).toThrow("simulated controller crash after pointer cleanup");
    expect(store.readActivePointer()).toMatchObject({
      activeReleaseId: "release-002",
      previousReleaseId: null,
      previousManifestSha256: null,
    });
    expect(existsSync(first.releaseDirectory)).toBe(true);
    expect(existsSync(second.releaseDirectory)).toBe(true);

    const recovered = store.finalizeForwardOnlyActivation({
      activeReleaseId: second.releaseId,
      activeManifestSha256: second.manifestSha256,
      supersededReleaseId: first.releaseId,
      supersededManifestSha256: first.manifestSha256,
    });
    expect(recovered).toMatchObject({
      activeReleaseId: "release-002",
      previousIdentityCleared: true,
      supersededReleaseDeleted: true,
    });
    expect(existsSync(first.releaseDirectory)).toBe(false);
    expect(existsSync(second.releaseDirectory)).toBe(true);

    expect(store.finalizeForwardOnlyActivation({
      activeReleaseId: second.releaseId,
      activeManifestSha256: second.manifestSha256,
      supersededReleaseId: first.releaseId,
      supersededManifestSha256: first.manifestSha256,
    })).toMatchObject({
      activeReleaseId: "release-002",
      previousIdentityCleared: true,
      supersededReleaseDeleted: false,
    });
    expect(store.pinActiveRelease().releaseId).toBe("release-002");
    expect(() => store.finalizeForwardOnlyActivation({
      activeReleaseId: second.releaseId,
      activeManifestSha256: second.manifestSha256,
      supersededReleaseId: second.releaseId,
      supersededManifestSha256: second.manifestSha256,
    })).toThrow("must never delete the active release");
    expect(existsSync(second.releaseDirectory)).toBe(true);
  });

  test("forward recovery deletes both superseded trees without deleting either active tree", () => {
    const { workspace, sourceDirectory, releaseRoot, store } = fixture();
    const first = store.stageRelease({
      releaseId: "release-001",
      sourceDirectory,
    });
    store.activateRelease(first.releaseId);
    writeFileSync(
      join(sourceDirectory, "index.html"),
      "<!doctype html><title>release two</title>\n",
    );
    const second = store.stageRelease({
      releaseId: "release-002",
      sourceDirectory,
    });
    store.activateRelease(second.releaseId);

    const serverReleaseRoot = join(
      workspace,
      "ti-scale-server-releases",
    );
    const previousApplicationTarget = join(
      serverReleaseRoot,
      "releases",
      "server-001",
    );
    const activeApplicationTarget = join(
      serverReleaseRoot,
      "releases",
      "server-002",
    );
    mkdirSync(previousApplicationTarget, { recursive: true });
    mkdirSync(activeApplicationTarget);
    writeFileSync(join(previousApplicationTarget, "server.js"), "old\n");
    writeFileSync(join(activeApplicationTarget, "server.js"), "active\n");

    expect(() => finalizeSupersededReleaseArtifacts({
      serverReleaseRoot,
      staticReleaseRoot: releaseRoot,
      activeServerReleaseId: "server-002",
      activeApplicationTarget,
      previousApplicationTarget,
      activeStaticReleaseId: second.releaseId,
      activeStaticManifestSha256: second.manifestSha256,
      previousStaticReleaseId: first.releaseId,
      previousStaticManifestSha256: first.manifestSha256,
      onStaticPreviousIdentityCleared: () => {
        throw new Error("simulated crash before release-tree deletion");
      },
    })).toThrow("simulated crash before release-tree deletion");
    expect(existsSync(previousApplicationTarget)).toBe(true);
    expect(existsSync(first.releaseDirectory)).toBe(true);
    expect(existsSync(activeApplicationTarget)).toBe(true);
    expect(existsSync(second.releaseDirectory)).toBe(true);

    expect(finalizeSupersededReleaseArtifacts({
      serverReleaseRoot,
      staticReleaseRoot: releaseRoot,
      activeServerReleaseId: "server-002",
      activeApplicationTarget,
      previousApplicationTarget,
      activeStaticReleaseId: second.releaseId,
      activeStaticManifestSha256: second.manifestSha256,
      previousStaticReleaseId: first.releaseId,
      previousStaticManifestSha256: first.manifestSha256,
    })).toEqual({
      staticPreviousIdentityCleared: true,
      staticReleaseDeleted: true,
      serverReleaseDeleted: true,
    });
    expect(existsSync(previousApplicationTarget)).toBe(false);
    expect(existsSync(first.releaseDirectory)).toBe(false);
    expect(existsSync(activeApplicationTarget)).toBe(true);
    expect(existsSync(second.releaseDirectory)).toBe(true);

    expect(finalizeSupersededReleaseArtifacts({
      serverReleaseRoot,
      staticReleaseRoot: releaseRoot,
      activeServerReleaseId: "server-002",
      activeApplicationTarget,
      previousApplicationTarget,
      activeStaticReleaseId: second.releaseId,
      activeStaticManifestSha256: second.manifestSha256,
      previousStaticReleaseId: first.releaseId,
      previousStaticManifestSha256: first.manifestSha256,
    })).toEqual({
      staticPreviousIdentityCleared: true,
      staticReleaseDeleted: false,
      serverReleaseDeleted: false,
    });
    expect(store.readActivePointer()).toMatchObject({
      activeReleaseId: "release-002",
      previousReleaseId: null,
      previousManifestSha256: null,
    });
  });

  test("SIGKILL releases the real activateRelease advisory lock for the next activation", async () => {
    const { workspace, sourceDirectory, releaseRoot, store } = fixture();
    store.stageRelease({ releaseId: "release-001", sourceDirectory });
    store.activateRelease("release-001");
    writeFileSync(join(sourceDirectory, "index.html"), "<!doctype html><title>release two</title>\n");
    writeFileSync(join(sourceDirectory, "assets", "app.js"), "globalThis.release = 'two';\n");
    store.stageRelease({ releaseId: "release-002", sourceDirectory });

    const marker = join(workspace, "child-lock-acquired");
    const childScript = join(workspace, "activate-and-block.ts");
    const storeModule = new URL("../StaticArtifactReleaseStore.ts", import.meta.url).href;
    writeFileSync(childScript, `
      import { writeFileSync } from "node:fs";
      import { StaticArtifactReleaseStore } from ${JSON.stringify(storeModule)};
      const [releaseRoot, marker] = process.argv.slice(2);
      if (!releaseRoot || !marker) throw new Error("missing subprocess arguments");
      const store = new StaticArtifactReleaseStore({
        releaseRoot,
        onLockAcquired: () => {
          writeFileSync(marker, "locked\\n");
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
        },
      });
      store.activateRelease("release-002");
    `);
    const child = Bun.spawn([process.execPath, childScript, releaseRoot, marker], {
      cwd: workspace,
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      stdout: "pipe",
      stderr: "pipe",
    });

    try {
      const deadline = Date.now() + 5_000;
      while (!existsSync(marker) && child.exitCode === null && Date.now() < deadline) {
        await Bun.sleep(10);
      }
      if (!existsSync(marker)) {
        const stderr = await new Response(child.stderr).text();
        throw new Error(`activateRelease child did not acquire the lock: ${stderr}`);
      }
      expectStaticError(() => store.activateRelease("release-002"), "release_locked");
      child.kill("SIGKILL");
      await child.exited;

      const activated = store.activateRelease("release-002");
      expect(activated.releaseId).toBe("release-002");
      expect(activated.pointerGeneration).toBe(2);
      expect(store.readActivePointer().activeReleaseId).toBe("release-002");
      const persistentLock = join(releaseRoot, ".static-artifact-handoff.lock");
      expect(existsSync(persistentLock)).toBe(true);
      expect(JSON.parse(readFileSync(persistentLock, "utf8"))).toMatchObject({
        schemaVersion: "ti-scale.static-artifact-lock-owner.v1",
        pid: process.pid,
      });
    } finally {
      if (child.exitCode === null) {
        child.kill("SIGKILL");
        await child.exited;
      }
    }
  });

  test("fails closed on a tampered, partial, or unmanifested copy without moving the active pointer", () => {
    const { sourceDirectory, releaseRoot, store } = fixture();
    store.stageRelease({ releaseId: "release-good", sourceDirectory });
    store.activateRelease("release-good");

    writeFileSync(join(sourceDirectory, "index.html"), "<!doctype html><title>tamper target</title>\n");
    store.stageRelease({ releaseId: "release-tampered", sourceDirectory });
    const tampered = join(releaseRoot, "releases", "release-tampered", "index.html");
    chmodSync(tampered, 0o644);
    writeFileSync(tampered, "tampered after immutable handoff\n");
    expectStaticError(() => store.verifyRelease("release-tampered"), "artifact_integrity_failed");
    expectStaticError(() => store.activateRelease("release-tampered"), "artifact_integrity_failed");
    expect(store.readActivePointer().activeReleaseId).toBe("release-good");

    store.stageRelease({ releaseId: "release-partial", sourceDirectory });
    const partialRoot = join(releaseRoot, "releases", "release-partial");
    chmodSync(join(partialRoot, "assets"), 0o755);
    unlinkSync(join(partialRoot, "assets", "app.js"));
    expectStaticError(() => store.verifyRelease("release-partial"), "artifact_integrity_failed");

    store.stageRelease({ releaseId: "release-extra", sourceDirectory });
    const extraRoot = join(releaseRoot, "releases", "release-extra");
    chmodSync(extraRoot, 0o755);
    writeFileSync(join(extraRoot, "unmanifested.txt"), "must fail\n");
    expectStaticError(() => store.verifyRelease("release-extra"), "artifact_integrity_failed");
  });

  test("rejects symlinks, special files, path escapes, legacy roots, and duplicate immutable IDs", () => {
    const { workspace, sourceDirectory, store } = fixture();
    writeFileSync(join(workspace, "outside.txt"), "outside\n");
    symlinkSync(join(workspace, "outside.txt"), join(sourceDirectory, "assets", "linked.js"));
    expectStaticError(
      () => store.stageRelease({ releaseId: "release-symlink", sourceDirectory }),
      "unsafe_artifact_source",
    );
    unlinkSync(join(sourceDirectory, "assets", "linked.js"));

    const fifo = join(sourceDirectory, "assets", "unexpected.fifo");
    const madeFifo = Bun.spawnSync(["mkfifo", fifo]);
    expect(madeFifo.exitCode).toBe(0);
    expectStaticError(
      () => store.stageRelease({ releaseId: "release-fifo", sourceDirectory }),
      "unsafe_artifact_source",
    );
    unlinkSync(fifo);

    expectStaticError(
      () => store.stageRelease({ releaseId: "../escape", sourceDirectory }),
      "invalid_release_id",
    );
    expectStaticError(
      () => new StaticArtifactReleaseStore({
        releaseRoot: join(workspace, "webapp", "ti-scale-releases"),
      }),
      "invalid_v2_release_path",
    );
    store.stageRelease({ releaseId: "release-once", sourceDirectory });
    expectStaticError(
      () => store.stageRelease({ releaseId: "release-once", sourceDirectory }),
      "release_already_exists",
    );
  });

  test("rejects direct CLI release mutation under the operator no-backup policy", () => {
    const { sourceDirectory, releaseRoot, store } = fixture();
    store.stageRelease({ releaseId: "release-001", sourceDirectory });
    store.activateRelease("release-001");
    writeFileSync(join(sourceDirectory, "index.html"), "<!doctype html><title>release two</title>\n");
    store.stageRelease({ releaseId: "release-002", sourceDirectory });
    store.activateRelease("release-002");
    expect(() => runStaticReleaseCli(["rollback", "--root", releaseRoot]))
      .toThrow("Direct static release mutation is disabled");
    expect(() => runStaticReleaseCli([
      "activate",
      "--root",
      releaseRoot,
      "--release-id",
      "release-001",
    ])).toThrow("Direct static release mutation is disabled");
    expect(store.pinActiveRelease().releaseId).toBe("release-002");
  });

  test("rejects a symlinked active pointer instead of following it", () => {
    const { workspace, sourceDirectory, releaseRoot, store } = fixture();
    store.stageRelease({ releaseId: "release-001", sourceDirectory });
    store.activateRelease("release-001");
    const pointer = join(releaseRoot, "state", STATIC_RELEASE_POINTER);
    unlinkSync(pointer);
    const outside = join(workspace, "outside-pointer.json");
    writeFileSync(outside, "{}\n");
    symlinkSync(outside, pointer);
    expectStaticError(() => store.pinActiveRelease(), "unsafe_artifact_source");
  });
});
