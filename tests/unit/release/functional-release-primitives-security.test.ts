import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { createHash } from "node:crypto";
import * as nodeFs from "node:fs";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import {
  exchangeApplicationTarget,
  verifyChecksumManifest,
  writeAndVerifyChecksumManifest,
  type ApplicationTargetSwapPhase,
  type ChecksumManifestPublicationPhase,
} from "../../../scripts/release/FunctionalReleasePrimitives";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temporaryRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  return root;
}

describe("release backup path and durability boundary", () => {
  test("rejects a bundle root reached through a symbolic-link ancestor", async () => {
    const root = temporaryRoot("ti-scale-checksum-root-symlink-");
    const realBundle = join(root, "real-bundle");
    const alias = join(root, "bundle-alias");
    mkdirSync(realBundle);
    writeFileSync(join(realBundle, "payload"), "bytes");
    symlinkSync(realBundle, alias);

    await expect(writeAndVerifyChecksumManifest(alias, ["payload"]))
      .rejects.toThrow("real directory without symbolic-link traversal");
  });

  test("rejects a payload whose nested parent symlink escapes the real bundle root", async () => {
    const root = temporaryRoot("ti-scale-checksum-symlink-");
    const bundle = join(root, "bundle");
    const outside = join(root, "outside");
    mkdirSync(bundle);
    mkdirSync(outside);
    writeFileSync(join(outside, "database.sqlite"), "escaped payload");
    symlinkSync(outside, join(bundle, "database"));

    await expect(writeAndVerifyChecksumManifest(bundle, ["database/database.sqlite"]))
      .rejects.toThrow("not a real regular file");

    const hash = createHash("sha256").update("escaped payload").digest("hex");
    writeFileSync(join(bundle, "SHA256SUMS"), `${hash}  database/database.sqlite\n`);
    await expect(verifyChecksumManifest(bundle))
      .rejects.toThrow("traverses a symbolic link");
  });

  test("syncs nested payload directories child-first before publishing SHA256SUMS", async () => {
    const root = temporaryRoot("ti-scale-checksum-durability-");
    const bundle = join(root, "bundle");
    const databaseDirectory = join(bundle, "database");
    const nestedDirectory = join(databaseDirectory, "snapshots");
    const payload = join(nestedDirectory, "ti-scale.sqlite");
    mkdirSync(nestedDirectory, { recursive: true });
    writeFileSync(payload, "durable database bytes");

    const operations: Array<
      | { readonly kind: "fsync"; readonly path: string; readonly file: boolean }
      | { readonly kind: "phase"; readonly phase: ChecksumManifestPublicationPhase }
    > = [];
    const realFsync = nodeFs.fsyncSync;
    const fsync = spyOn(nodeFs, "fsyncSync").mockImplementation((descriptor: number) => {
      const metadata = nodeFs.fstatSync(descriptor);
      operations.push({
        kind: "fsync",
        path: nodeFs.readlinkSync(`/proc/self/fd/${String(descriptor)}`),
        file: metadata.isFile(),
      });
      realFsync(descriptor);
    });
    try {
      await writeAndVerifyChecksumManifest(bundle, ["database/snapshots/ti-scale.sqlite"], {
        onPhase: (phase) => { operations.push({ kind: "phase", phase }); },
      });
    } finally { fsync.mockRestore(); }

    const directoryBoundary = operations.findIndex(
      (operation) => operation.kind === "phase" && operation.phase === "payload_directory_synced",
    );
    const beforeManifest = operations.slice(0, directoryBoundary);
    const syncedPaths = beforeManifest
      .filter((operation): operation is Extract<typeof operation, { kind: "fsync" }> => operation.kind === "fsync")
      .map((operation) => operation.path);
    expect(syncedPaths).toEqual([payload, nestedDirectory, databaseDirectory, bundle]);
    expect(operations.slice(directoryBoundary + 1).some(
      (operation) => operation.kind === "phase" && operation.phase === "manifest_renamed",
    )).toBe(true);
  });
});

describe("atomic application exchange durability boundary", () => {
  function fixture(): {
    readonly root: string;
    readonly applicationPath: string;
    readonly oldTarget: string;
    readonly newTarget: string;
    readonly archive: string;
  } {
    const root = temporaryRoot("ti-scale-exchange-durability-");
    const releases = join(root, "releases");
    const oldTarget = join(releases, "old");
    const newTarget = join(releases, "new");
    const applicationPath = join(root, "ti-scale");
    mkdirSync(oldTarget, { recursive: true });
    mkdirSync(newTarget, { recursive: true });
    writeFileSync(join(oldTarget, "identity"), "old");
    writeFileSync(join(newTarget, "identity"), "new");
    symlinkSync(oldTarget, applicationPath);
    return { root, applicationPath, oldTarget, newTarget, archive: join(root, "archive", "old") };
  }

  test("does not return until exchange and displaced-entry removal are directory-durable", () => {
    const value = fixture();
    const phases: ApplicationTargetSwapPhase[] = [];
    const result = exchangeApplicationTarget({
      applicationPath: value.applicationPath,
      newTarget: value.newTarget,
      previousDirectoryArchive: value.archive,
      swapName: "durability-order",
      onPhase: (phase) => { phases.push(phase); },
    });

    expect(phases).toEqual([
      "prepared_swap_directory_synced",
      "exchanged",
      "exchange_directory_synced",
      "displaced_finalized",
      "displaced_parent_synced",
    ]);
    expect(realpathSync(value.applicationPath)).toBe(realpathSync(value.newTarget));
    expect(result).toEqual({
      activeTarget: value.newTarget,
      previousTarget: value.oldTarget,
      previousKind: "symlink",
    });
    expect(existsSync(join(value.root, ".ti-scale.durability-order.swap"))).toBe(false);
  });

  test("an exchange-directory fsync fault rolls the atomic target back before throwing", () => {
    const value = fixture();
    const realFsync = nodeFs.fsyncSync;
    let applicationParentSyncs = 0;
    const fsync = spyOn(nodeFs, "fsyncSync").mockImplementation((descriptor: number) => {
      const path = nodeFs.readlinkSync(`/proc/self/fd/${String(descriptor)}`);
      if (!nodeFs.fstatSync(descriptor).isFile() && path === value.root) {
        applicationParentSyncs += 1;
        if (applicationParentSyncs === 2) {
          throw Object.assign(new Error("simulated exchange parent fsync failure"), { code: "EIO" });
        }
      }
      realFsync(descriptor);
    });
    try {
      expect(() => exchangeApplicationTarget({
        applicationPath: value.applicationPath,
        newTarget: value.newTarget,
        previousDirectoryArchive: value.archive,
        swapName: "fsync-fault",
      })).toThrow("simulated exchange parent fsync failure");
    } finally { fsync.mockRestore(); }

    expect(lstatSync(value.applicationPath).isSymbolicLink()).toBe(true);
    expect(realpathSync(value.applicationPath)).toBe(realpathSync(value.oldTarget));
    expect(readlinkSync(value.applicationPath)).toBe(value.oldTarget);
    expect(existsSync(join(value.root, `.ti-scale.fsync-fault.swap`))).toBe(false);
  });

  test("a displaced directory is archived only after both rename parents are durable", () => {
    const value = fixture();
    rmSync(value.applicationPath);
    mkdirSync(value.applicationPath);
    writeFileSync(join(value.applicationPath, "identity"), "legacy directory");
    const phases: ApplicationTargetSwapPhase[] = [];

    const result = exchangeApplicationTarget({
      applicationPath: value.applicationPath,
      newTarget: value.newTarget,
      previousDirectoryArchive: value.archive,
      swapName: "directory-archive",
      onPhase: (phase) => { phases.push(phase); },
    });

    expect(phases).toEqual([
      "prepared_swap_directory_synced",
      "exchanged",
      "exchange_directory_synced",
      "displaced_finalized",
      "displaced_parent_synced",
    ]);
    expect(realpathSync(value.applicationPath)).toBe(realpathSync(value.newTarget));
    expect(lstatSync(value.archive).isDirectory()).toBe(true);
    expect(result.previousKind).toBe("directory");
    expect(result.previousTarget).toBe(value.archive);
  });

  test("an archive-parent fsync fault restores the displaced directory and active path", () => {
    const value = fixture();
    rmSync(value.applicationPath);
    mkdirSync(value.applicationPath);
    writeFileSync(join(value.applicationPath, "identity"), "legacy directory");
    const archiveParent = join(value.root, "archive");
    const realFsync = nodeFs.fsyncSync;
    let archiveParentSyncs = 0;
    const fsync = spyOn(nodeFs, "fsyncSync").mockImplementation((descriptor: number) => {
      const path = nodeFs.readlinkSync(`/proc/self/fd/${String(descriptor)}`);
      if (!nodeFs.fstatSync(descriptor).isFile() && path === archiveParent) {
        archiveParentSyncs += 1;
        if (archiveParentSyncs === 2) {
          throw Object.assign(new Error("simulated archive parent fsync failure"), { code: "EIO" });
        }
      }
      realFsync(descriptor);
    });
    try {
      expect(() => exchangeApplicationTarget({
        applicationPath: value.applicationPath,
        newTarget: value.newTarget,
        previousDirectoryArchive: value.archive,
        swapName: "archive-fsync-fault",
      })).toThrow("simulated archive parent fsync failure");
    } finally { fsync.mockRestore(); }

    expect(lstatSync(value.applicationPath).isDirectory()).toBe(true);
    expect(nodeFs.readFileSync(join(value.applicationPath, "identity"), "utf8")).toBe("legacy directory");
    expect(existsSync(value.archive)).toBe(false);
    expect(existsSync(join(value.root, ".ti-scale.archive-fsync-fault.swap"))).toBe(false);
  });
});
