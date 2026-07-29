import { afterEach, describe, expect, spyOn, test } from "bun:test";
import * as nodeFs from "node:fs";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import {
  stageServerRelease,
  type ServerReleaseStagingPhase,
} from "../../../scripts/release/FunctionalReleasePrimitives";

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

function fixture(): { readonly source: string; readonly releaseContainer: string } {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-server-durability-"));
  roots.push(root);
  const source = join(root, "source");
  const releaseContainer = join(root, "server-releases");
  mkdirSync(join(source, "server", "nested", "leaf"), { recursive: true });
  mkdirSync(join(source, "node_modules", ".bin"), { recursive: true });
  writeFileSync(join(source, "package.json"), "{\"name\":\"durability-fixture\"}\n");
  writeFileSync(join(source, "server", "index.ts"), "export {};\n");
  writeFileSync(join(source, "server", "nested", "leaf", "payload.ts"), "export const durable = true;\n");
  writeFileSync(join(source, "node_modules", "tool.js"), "export {};\n");
  symlinkSync("../tool.js", join(source, "node_modules", ".bin", "tool"));
  return { source, releaseContainer };
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    makeWritable(root);
    rmSync(root, { recursive: true, force: true });
  }
});

describe("server release durability", () => {
  test("syncs bytes, leaf directories, the staging root, and both promotion directories in order", async () => {
    const { source, releaseContainer } = fixture();
    type Operation =
      | { readonly kind: "file" | "directory"; readonly path: string }
      | { readonly kind: "phase"; readonly phase: ServerReleaseStagingPhase };
    const operations: Operation[] = [];
    const realFsyncSync = nodeFs.fsyncSync;
    const fsync = spyOn(nodeFs, "fsyncSync").mockImplementation((descriptor: number) => {
      const metadata = nodeFs.fstatSync(descriptor);
      operations.push({
        kind: metadata.isFile() ? "file" : "directory",
        path: nodeFs.readlinkSync(`/proc/self/fd/${descriptor}`),
      });
      realFsyncSync(descriptor);
    });
    let release: Awaited<ReturnType<typeof stageServerRelease>>;
    try {
      release = await stageServerRelease({
        sourceRoot: source,
        releaseRoot: releaseContainer,
        releaseId: "candidate-durable-order",
        onPhase: (phase) => { operations.push({ kind: "phase", phase }); },
      });
    } finally { fsync.mockRestore(); }

    const phases = operations
      .filter((operation): operation is Extract<Operation, { kind: "phase" }> => operation.kind === "phase")
      .map((operation) => operation.phase);
    expect(phases).toEqual([
      "release_layout_synced",
      "regular_files_synced",
      "nested_directories_synced",
      "staging_directory_synced",
      "renamed",
      "promoted_directory_synced",
      "release_root_synced",
    ]);
    const phaseIndex = (phase: ServerReleaseStagingPhase): number => operations.findIndex(
      (operation) => operation.kind === "phase" && operation.phase === phase,
    );
    const layoutSynced = phaseIndex("release_layout_synced");
    const filesSynced = phaseIndex("regular_files_synced");
    const nestedDirectoriesSynced = phaseIndex("nested_directories_synced");
    const stagingDirectorySynced = phaseIndex("staging_directory_synced");
    const renamed = phaseIndex("renamed");
    const promotedDirectorySynced = phaseIndex("promoted_directory_synced");

    const layoutOperations = operations.slice(0, layoutSynced);
    expect(layoutOperations).toEqual([
      { kind: "directory", path: join(releaseContainer, "releases") },
      { kind: "directory", path: releaseContainer },
      { kind: "directory", path: dirname(releaseContainer) },
    ]);

    const fileOperations = operations.slice(layoutSynced + 1, filesSynced);
    expect(fileOperations.every((operation) => operation.kind === "file")).toBe(true);
    expect(fileOperations).toHaveLength(
      release.manifest.entries.filter((entry) => entry.kind === "file").length + 1,
    );
    expect(fileOperations.some(
      (operation) => operation.kind === "file" && operation.path.endsWith("/server-release-manifest.json"),
    )).toBe(true);

    const nestedDirectoryOperations = operations.slice(filesSynced + 1, nestedDirectoriesSynced);
    expect(nestedDirectoryOperations.length).toBeGreaterThan(0);
    expect(nestedDirectoryOperations.every((operation) => operation.kind === "directory")).toBe(true);
    const nestedPaths = nestedDirectoryOperations.map((operation) => (
      operation.kind === "directory" ? operation.path : ""
    ));
    for (const [index, path] of nestedPaths.entries()) {
      const parentIndex = nestedPaths.indexOf(dirname(path));
      if (parentIndex !== -1) expect(parentIndex).toBeGreaterThan(index);
    }

    const stagingSync = operations[stagingDirectorySynced - 1];
    expect(stagingSync?.kind).toBe("directory");
    if (stagingSync?.kind === "directory") {
      expect(basename(stagingSync.path)).toStartWith(".stage-candidate-durable-order-");
    }
    expect(operations[renamed + 1]).toEqual({ kind: "directory", path: release.releaseDirectory });
    expect(operations[promotedDirectorySynced + 1]).toEqual({
      kind: "directory",
      path: join(releaseContainer, "releases"),
    });
  });

  test("fails closed on fsync faults and never promotes before the staged tree is durable", async () => {
    const scenarios = [
      {
        target: "layout-parent",
        completedPhases: [] as ServerReleaseStagingPhase[],
        prePromotion: true,
      },
      {
        target: "regular-file",
        completedPhases: ["release_layout_synced"] as ServerReleaseStagingPhase[],
        prePromotion: true,
      },
      {
        target: "leaf-directory",
        completedPhases: ["release_layout_synced", "regular_files_synced"] as ServerReleaseStagingPhase[],
        prePromotion: true,
      },
      {
        target: "staging-directory",
        completedPhases: [
          "release_layout_synced", "regular_files_synced", "nested_directories_synced",
        ] as ServerReleaseStagingPhase[],
        prePromotion: true,
      },
      {
        target: "promoted-directory",
        completedPhases: [
          "release_layout_synced", "regular_files_synced", "nested_directories_synced",
          "staging_directory_synced", "renamed",
        ] as ServerReleaseStagingPhase[],
        prePromotion: false,
      },
      {
        target: "release-root",
        completedPhases: [
          "release_layout_synced", "regular_files_synced", "nested_directories_synced",
          "staging_directory_synced", "renamed", "promoted_directory_synced",
        ] as ServerReleaseStagingPhase[],
        prePromotion: false,
      },
    ] as const;

    for (const scenario of scenarios) {
      const { source, releaseContainer } = fixture();
      const releaseId = `candidate-fsync-${scenario.target}`;
      const releaseRoot = join(releaseContainer, "releases");
      const destination = join(releaseRoot, releaseId);
      const phases: ServerReleaseStagingPhase[] = [];
      const realFsyncSync = nodeFs.fsyncSync;
      let injected = false;
      const fsync = spyOn(nodeFs, "fsyncSync").mockImplementation((descriptor: number) => {
        const metadata = nodeFs.fstatSync(descriptor);
        const path = nodeFs.readlinkSync(`/proc/self/fd/${descriptor}`);
        const stagingRoot = metadata.isDirectory()
          && dirname(path) === releaseRoot && basename(path).startsWith(`.stage-${releaseId}-`);
        const matches = scenario.target === "layout-parent"
          ? metadata.isDirectory() && path === releaseContainer
          : scenario.target === "regular-file"
          ? metadata.isFile() && path.endsWith("/server/index.ts")
          : scenario.target === "leaf-directory"
            ? metadata.isDirectory() && path.endsWith("/node_modules/.bin")
            : scenario.target === "staging-directory"
              ? stagingRoot
              : scenario.target === "promoted-directory"
                ? metadata.isDirectory() && path === destination
                : metadata.isDirectory() && path === releaseRoot &&
                  phases.includes("promoted_directory_synced");
        if (matches) {
          injected = true;
          throw Object.assign(new Error(`simulated ${scenario.target} fsync failure`), { code: "EIO" });
        }
        realFsyncSync(descriptor);
      });
      try {
        await expect(stageServerRelease({
          sourceRoot: source,
          releaseRoot: releaseContainer,
          releaseId,
          onPhase: (phase) => { phases.push(phase); },
        })).rejects.toThrow(`simulated ${scenario.target} fsync failure`);
      } finally { fsync.mockRestore(); }

      expect(injected).toBe(true);
      expect(phases).toEqual(scenario.completedPhases);
      expect(existsSync(destination)).toBe(!scenario.prePromotion);
      expect(readdirSync(releaseRoot).some((name) => name.startsWith(`.stage-${releaseId}-`))).toBe(false);
    }
  });
});
