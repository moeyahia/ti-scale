import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
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
import { join } from "node:path";
import { runStaticReleaseCli } from "../cli";
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

  test("retains the prior version and pointer rollback returns only to its verified manifest", () => {
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

    const rolledBack = store.rollbackPointer();
    expect(rolledBack.releaseId).toBe("release-001");
    expect(rolledBack.pointerGeneration).toBe(3);
    expect(store.readActivePointer()).toMatchObject({
      activeReleaseId: "release-001",
      previousReleaseId: "release-002",
      previousManifestSha256: second.manifestSha256,
    });
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

  test("refuses rollback when the recorded prior release no longer verifies", () => {
    const { sourceDirectory, releaseRoot, store } = fixture();
    store.stageRelease({ releaseId: "release-001", sourceDirectory });
    store.activateRelease("release-001");
    writeFileSync(join(sourceDirectory, "index.html"), "<!doctype html><title>release two</title>\n");
    store.stageRelease({ releaseId: "release-002", sourceDirectory });
    store.activateRelease("release-002");

    const priorIndex = join(releaseRoot, "releases", "release-001", "index.html");
    chmodSync(priorIndex, 0o644);
    writeFileSync(priorIndex, "tampered prior\n");
    expectStaticError(() => store.rollbackPointer(), "artifact_integrity_failed");
    expect(store.readActivePointer()).toMatchObject({
      activeReleaseId: "release-002",
      previousReleaseId: "release-001",
      generation: 2,
    });
  });

  test("exposes a one-command CLI pointer rollback with an explicit static-only warning", () => {
    const { sourceDirectory, releaseRoot, store } = fixture();
    store.stageRelease({ releaseId: "release-001", sourceDirectory });
    store.activateRelease("release-001");
    writeFileSync(join(sourceDirectory, "index.html"), "<!doctype html><title>release two</title>\n");
    store.stageRelease({ releaseId: "release-002", sourceDirectory });
    store.activateRelease("release-002");
    let output = "";

    expect(runStaticReleaseCli(["rollback", "--root", releaseRoot], {
      write: (value) => { output += value; },
    })).toBe(0);
    expect(JSON.parse(output)).toMatchObject({
      operation: "rollback",
      scope: "v2_static_artifact_pointer_only",
      result: { releaseId: "release-001", pointerGeneration: 3 },
    });
    expect(output).toContain("does not cut over or roll back API, database, workers");
    expect(store.pinActiveRelease().releaseId).toBe("release-001");
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
