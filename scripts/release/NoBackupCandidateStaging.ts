import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readlinkSync,
  realpathSync,
  rmSync,
} from "node:fs";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import {
  fingerprintServerReleaseSource,
  stageServerRelease,
  verifyServerRelease,
  type VerifiedServerRelease,
} from "./FunctionalReleasePrimitives";
import {
  StaticArtifactReleaseStore,
  fingerprintStaticArtifactSource,
  type VerifiedStaticRelease,
} from "../../server/static-release";
import {
  NO_BACKUP_APPLICATION_PATH,
  NO_BACKUP_PAYLOAD_ROOTS,
  NO_BACKUP_SERVER_RELEASE_ROOT,
  NO_BACKUP_STATIC_RELEASE_ROOT,
  assertNoBackupPayloadInventoryEmpty,
  assertNoBackupPayloadInventoryUnchanged,
  captureNoBackupPayloadInventory,
  runNoBackupPreviewReleaseWithCandidate,
  type NoBackupCandidateLifecycle,
  type NoBackupPreviewReceipt,
  type NoBackupStagedCandidateBinding,
} from "./NoBackupPreviewRelease";
import {
  runBoundedReleaseCommandSync,
} from "./BoundedReleaseCommand";

export const NO_BACKUP_CANDIDATE_BINDING_SCHEMA =
  "ti-scale.no-backup-candidate-staging-binding.v1" as const;

const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const GIT_COMMIT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;

export interface NoBackupCandidateSourceInspection {
  readonly schemaVersion:
    "ti-scale.no-backup-candidate-source-inspection.v1";
  readonly sourceRoot: string;
  readonly staticBuildRoot: string;
  readonly sourceCommit: string;
  readonly sourceTreeSha256: string;
  readonly staticArtifactSha256: string;
  readonly sourceEntryCount: number;
  readonly sourceBytes: number;
  readonly staticEntryCount: number;
  readonly staticBytes: number;
  readonly gitStatus: "clean";
}

export interface NoBackupCandidatePins {
  readonly sourceCommit: string;
  readonly sourceTreeSha256: string;
  readonly staticArtifactSha256: string;
}

export interface NoBackupCandidateStagingInput
  extends NoBackupCandidatePins {
  readonly releaseId: string;
  readonly sourceRoot: string;
  readonly staticBuildRoot: string;
  readonly serverReleaseRoot: string;
  readonly staticReleaseRoot: string;
  readonly applicationPath: string;
}

export interface StagedNoBackupCandidate {
  readonly binding: NoBackupStagedCandidateBinding;
  readonly createdServerRelease: boolean;
  readonly createdStaticRelease: boolean;
}

export interface NoBackupCandidateCliDependencies {
  readonly serverReleaseRoot?: string;
  readonly staticReleaseRoot?: string;
  readonly applicationPath?: string;
  readonly runRelease?: (
    argv: readonly string[],
    lifecycle: NoBackupCandidateLifecycle,
  ) => Promise<NoBackupPreviewReceipt>;
}

export type NoBackupCandidateCliResult =
  | {
    readonly command: "inspect";
    readonly inspection: NoBackupCandidateSourceInspection;
  }
  | {
    readonly command: "stage-deploy";
    readonly receipt: NoBackupPreviewReceipt;
  };

function minimalEnvironment(): NodeJS.ProcessEnv {
  return {
    PATH:
      "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: "/root",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NO_COLOR: "1",
    CI: "1",
  };
}

function git(sourceRoot: string, args: readonly string[]): string {
  return runBoundedReleaseCommandSync([
    "/usr/bin/git",
    "-C",
    sourceRoot,
    ...args,
  ], {
    cwd: "/",
    env: minimalEnvironment(),
    stdin: "ignore",
    timeoutMs: 60_000,
    outputLimitBytes: 4 * 1024 * 1024,
  }).stdout.trim();
}

function isNodeError(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function realDirectory(pathValue: string, label: string): string {
  if (!pathValue.trim() || !isAbsolute(pathValue)) {
    throw new Error(`${label} must be an explicit absolute path`);
  }
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    realpathSync(path) !== path
  ) {
    throw new Error(
      `${label} must be one real directory without symbolic-link traversal`,
    );
  }
  return path;
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return (
    child === "" ||
    (!isAbsolute(child) &&
      child !== ".." &&
      !child.startsWith(`..${sep}`))
  );
}

function assertDisjointReleaseRoot(
  sourceRoot: string,
  releaseRoot: string,
  label: string,
): void {
  const normalizedReleaseRoot = resolve(releaseRoot);
  if (
    containedBy(sourceRoot, normalizedReleaseRoot) ||
    containedBy(normalizedReleaseRoot, sourceRoot)
  ) {
    throw new Error(`${label} must be disjoint from the clean source tree`);
  }
}

function assertCleanGitState(
  sourceRoot: string,
): { readonly commit: string } {
  const topLevel = realDirectory(
    git(sourceRoot, ["rev-parse", "--show-toplevel"]),
    "Git worktree root",
  );
  if (topLevel !== sourceRoot) {
    throw new Error(
      "--source-root must be the exact root of its Git worktree",
    );
  }
  const commit = git(sourceRoot, [
    "rev-parse",
    "--verify",
    "HEAD^{commit}",
  ]).toLowerCase();
  if (!GIT_COMMIT.test(commit)) {
    throw new Error("Clean source HEAD is not a full pinned Git commit");
  }
  const status = git(sourceRoot, [
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
  ]);
  if (status) {
    throw new Error(
      "No-backup candidate staging requires a clean Git worktree",
    );
  }
  return { commit };
}

export async function inspectNoBackupCandidateSource(input: {
  readonly sourceRoot: string;
  readonly staticBuildRoot: string;
}): Promise<NoBackupCandidateSourceInspection> {
  const sourceRoot = realDirectory(input.sourceRoot, "Source root");
  const staticBuildRoot = realDirectory(
    input.staticBuildRoot,
    "Static build root",
  );
  if (staticBuildRoot !== join(sourceRoot, "dist")) {
    throw new Error(
      "--static-build-root must be the clean source tree's exact dist directory",
    );
  }
  if (
    !existsSync(join(sourceRoot, "package.json")) ||
    !existsSync(join(sourceRoot, "server", "index.ts"))
  ) {
    throw new Error(
      "Clean source is missing package.json or server/index.ts",
    );
  }
  const before = assertCleanGitState(sourceRoot);
  const source = await fingerprintServerReleaseSource(sourceRoot);
  const browser = fingerprintStaticArtifactSource(staticBuildRoot);
  const after = assertCleanGitState(sourceRoot);
  if (before.commit !== after.commit) {
    throw new Error(
      "Clean source HEAD changed while candidate identities were inspected",
    );
  }
  return {
    schemaVersion:
      "ti-scale.no-backup-candidate-source-inspection.v1",
    sourceRoot,
    staticBuildRoot,
    sourceCommit: after.commit,
    sourceTreeSha256: source.treeSha256,
    staticArtifactSha256: browser.artifactSha256,
    sourceEntryCount: source.entryCount,
    sourceBytes: source.totalBytes,
    staticEntryCount: browser.entryCount,
    staticBytes: browser.totalBytes,
    gitStatus: "clean",
  };
}

function assertPins(
  inspection: NoBackupCandidateSourceInspection,
  pins: NoBackupCandidatePins,
): void {
  if (
    !GIT_COMMIT.test(pins.sourceCommit) ||
    pins.sourceCommit !== inspection.sourceCommit
  ) {
    throw new Error(
      "Pinned source commit does not match the clean Git worktree",
    );
  }
  if (
    !SHA256.test(pins.sourceTreeSha256) ||
    pins.sourceTreeSha256 !== inspection.sourceTreeSha256
  ) {
    throw new Error(
      "Pinned server source tree SHA-256 does not match the clean source",
    );
  }
  if (
    !SHA256.test(pins.staticArtifactSha256) ||
    pins.staticArtifactSha256 !==
      inspection.staticArtifactSha256
  ) {
    throw new Error(
      "Pinned static artifact SHA-256 does not match the explicit build",
    );
  }
}

function syncDirectory(path: string): void {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY,
  );
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function candidateDirectory(
  releaseRoot: string,
  releaseId: string,
): string {
  const directory = join(resolve(releaseRoot), "releases", releaseId);
  if (
    dirname(directory) !== join(resolve(releaseRoot), "releases") ||
    basename(directory) !== releaseId
  ) {
    throw new Error("Candidate path is not an exact managed release path");
  }
  return directory;
}

function candidateExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (isNodeError(error, "ENOENT")) return false;
    throw error;
  }
}

function assertExactCandidateDirectory(
  path: string,
  label: string,
): void {
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    realpathSync(path) !== resolve(path)
  ) {
    throw new Error(`${label} is not an exact immutable directory`);
  }
}

function activeApplicationTarget(applicationPath: string): string {
  const normalized = resolve(applicationPath);
  const metadata = lstatSync(normalized);
  if (!metadata.isSymbolicLink()) {
    throw new Error(
      "No-backup candidate staging requires the active application path to be a symbolic link",
    );
  }
  const linkTarget = readlinkSync(normalized);
  const target = realpathSync(resolve(dirname(normalized), linkTarget));
  return target;
}

async function verifyCandidatePair(input: {
  readonly releaseId: string;
  readonly serverReleaseRoot: string;
  readonly staticReleaseRoot: string;
  readonly sourceTreeSha256: string;
  readonly staticArtifactSha256: string;
}): Promise<{
  readonly server: VerifiedServerRelease;
  readonly static: VerifiedStaticRelease;
}> {
  const server = await verifyServerRelease(
    candidateDirectory(input.serverReleaseRoot, input.releaseId),
    input.releaseId,
  );
  if (server.manifest.treeSha256 !== input.sourceTreeSha256) {
    throw new Error(
      "Candidate server release does not match the pinned clean source tree",
    );
  }
  const browser = new StaticArtifactReleaseStore({
    releaseRoot: input.staticReleaseRoot,
  }).verifyRelease(input.releaseId);
  if (
    browser.manifest.artifactSha256 !==
      input.staticArtifactSha256
  ) {
    throw new Error(
      "Candidate static release does not match the pinned browser build",
    );
  }
  return { server, static: browser };
}

export async function discardUnpublishedNoBackupCandidate(input: {
  readonly releaseId: string;
  readonly serverReleaseRoot: string;
  readonly staticReleaseRoot: string;
  readonly applicationPath: string;
  readonly sourceTreeSha256: string;
  readonly staticArtifactSha256: string;
  readonly deleteServerRelease: boolean;
  readonly deleteStaticRelease: boolean;
}): Promise<{
  readonly serverReleaseDeleted: boolean;
  readonly staticReleaseDeleted: boolean;
}> {
  if (!RELEASE_ID.test(input.releaseId)) {
    throw new Error("Candidate release ID is invalid");
  }
  const serverDirectory = candidateDirectory(
    input.serverReleaseRoot,
    input.releaseId,
  );
  const staticDirectory = candidateDirectory(
    input.staticReleaseRoot,
    input.releaseId,
  );
  const activeServer = activeApplicationTarget(input.applicationPath);
  if (
    input.deleteServerRelease &&
    resolve(serverDirectory) === resolve(activeServer)
  ) {
    throw new Error(
      "Unpublished cleanup must never delete the active server release",
    );
  }
  const staticStore = new StaticArtifactReleaseStore({
    releaseRoot: input.staticReleaseRoot,
  });
  const pointer = staticStore.readActivePointer();
  if (
    input.deleteStaticRelease &&
    (
      pointer.activeReleaseId === input.releaseId ||
      pointer.previousReleaseId === input.releaseId
    )
  ) {
    throw new Error(
      "Unpublished cleanup refuses a static release retained by the active pointer",
    );
  }

  const serverPresent =
    input.deleteServerRelease && candidateExists(serverDirectory);
  const staticPresent =
    input.deleteStaticRelease && candidateExists(staticDirectory);

  // Verify every deletion target before removing either half. A tampered or
  // pointer-retained tree is preserved for diagnosis rather than partially
  // erased.
  if (serverPresent) {
    assertExactCandidateDirectory(
      serverDirectory,
      "Unpublished candidate server release",
    );
    const verified = await verifyServerRelease(
      serverDirectory,
      input.releaseId,
    );
    if (verified.manifest.treeSha256 !== input.sourceTreeSha256) {
      throw new Error(
        "Unpublished candidate server release differs from its pinned identity",
      );
    }
  }
  if (staticPresent) {
    assertExactCandidateDirectory(
      staticDirectory,
      "Unpublished candidate static release",
    );
    const verified = staticStore.verifyRelease(input.releaseId);
    if (
      verified.manifest.artifactSha256 !==
        input.staticArtifactSha256
    ) {
      throw new Error(
        "Unpublished candidate static release differs from its pinned identity",
      );
    }
  }

  let staticReleaseDeleted = false;
  if (staticPresent) {
    rmSync(staticDirectory, { recursive: true, force: false });
    syncDirectory(dirname(staticDirectory));
    staticReleaseDeleted = true;
  }
  let serverReleaseDeleted = false;
  if (serverPresent) {
    rmSync(serverDirectory, { recursive: true, force: false });
    syncDirectory(dirname(serverDirectory));
    serverReleaseDeleted = true;
  }
  return { serverReleaseDeleted, staticReleaseDeleted };
}

export async function stageNoBackupCandidatePair(
  input: NoBackupCandidateStagingInput,
): Promise<StagedNoBackupCandidate> {
  if (!RELEASE_ID.test(input.releaseId)) {
    throw new Error("A safe immutable release ID is required");
  }
  const sourceRoot = realDirectory(input.sourceRoot, "Source root");
  const staticBuildRoot = realDirectory(
    input.staticBuildRoot,
    "Static build root",
  );
  assertDisjointReleaseRoot(
    sourceRoot,
    input.serverReleaseRoot,
    "Server release root",
  );
  assertDisjointReleaseRoot(
    sourceRoot,
    input.staticReleaseRoot,
    "Static release root",
  );
  const inspection = await inspectNoBackupCandidateSource({
    sourceRoot,
    staticBuildRoot,
  });
  assertPins(inspection, input);

  const inventoryBefore = captureNoBackupPayloadInventory(
    NO_BACKUP_PAYLOAD_ROOTS,
  );
  assertNoBackupPayloadInventoryEmpty(inventoryBefore);

  const serverDirectory = candidateDirectory(
    input.serverReleaseRoot,
    input.releaseId,
  );
  const staticDirectory = candidateDirectory(
    input.staticReleaseRoot,
    input.releaseId,
  );
  const serverPreexisted = candidateExists(serverDirectory);
  const staticPreexisted = candidateExists(staticDirectory);
  let createdServerRelease = false;
  let createdStaticRelease = false;

  const staticStore = new StaticArtifactReleaseStore({
    releaseRoot: input.staticReleaseRoot,
  });
  const activeStatic = staticStore.readActivePointer();
  if (
    activeStatic.activeReleaseId === input.releaseId ||
    activeStatic.previousReleaseId === input.releaseId
  ) {
    throw new Error(
      "Candidate release ID is already retained by the active static pointer",
    );
  }
  if (
    resolve(activeApplicationTarget(input.applicationPath)) ===
      resolve(serverDirectory)
  ) {
    throw new Error(
      "Candidate release ID is already the active server release",
    );
  }

  try {
    if (serverPreexisted) {
      const server = await verifyServerRelease(
        serverDirectory,
        input.releaseId,
      );
      if (server.manifest.treeSha256 !== input.sourceTreeSha256) {
        throw new Error(
          "Existing server candidate differs from the pinned clean source tree",
        );
      }
    } else {
      await stageServerRelease({
        sourceRoot,
        releaseRoot: input.serverReleaseRoot,
        releaseId: input.releaseId,
      });
      createdServerRelease = true;
    }

    if (staticPreexisted) {
      const browser = staticStore.verifyRelease(input.releaseId);
      if (
        browser.manifest.artifactSha256 !==
          input.staticArtifactSha256
      ) {
        throw new Error(
          "Existing static candidate differs from the pinned browser build",
        );
      }
    } else {
      staticStore.stageRelease({
        releaseId: input.releaseId,
        sourceDirectory: staticBuildRoot,
      });
      createdStaticRelease = true;
    }

    const after = await inspectNoBackupCandidateSource({
      sourceRoot,
      staticBuildRoot,
    });
    assertPins(after, input);
    const verified = await verifyCandidatePair({
      releaseId: input.releaseId,
      serverReleaseRoot: input.serverReleaseRoot,
      staticReleaseRoot: input.staticReleaseRoot,
      sourceTreeSha256: input.sourceTreeSha256,
      staticArtifactSha256: input.staticArtifactSha256,
    });
    const inventoryAfter = captureNoBackupPayloadInventory(
      NO_BACKUP_PAYLOAD_ROOTS,
    );
    assertNoBackupPayloadInventoryEmpty(inventoryAfter);
    assertNoBackupPayloadInventoryUnchanged(
      inventoryBefore,
      inventoryAfter,
    );
    return {
      binding: {
        schemaVersion: NO_BACKUP_CANDIDATE_BINDING_SCHEMA,
        releaseId: input.releaseId,
        sourceCommit: input.sourceCommit,
        sourceTreeSha256: input.sourceTreeSha256,
        staticArtifactSha256: input.staticArtifactSha256,
        serverRelease: {
          path: verified.server.releaseDirectory,
          manifestSha256: verified.server.manifestSha256,
          treeSha256: verified.server.manifest.treeSha256,
        },
        staticRelease: {
          path: verified.static.releaseDirectory,
          manifestSha256: verified.static.manifestSha256,
          artifactSha256:
            verified.static.manifest.artifactSha256,
        },
      },
      createdServerRelease,
      createdStaticRelease,
    };
  } catch (error) {
    if (!serverPreexisted && candidateExists(serverDirectory)) {
      createdServerRelease = true;
    }
    if (!staticPreexisted && candidateExists(staticDirectory)) {
      createdStaticRelease = true;
    }
    if (createdServerRelease || createdStaticRelease) {
      try {
        await discardUnpublishedNoBackupCandidate({
          releaseId: input.releaseId,
          serverReleaseRoot: input.serverReleaseRoot,
          staticReleaseRoot: input.staticReleaseRoot,
          applicationPath: input.applicationPath,
          sourceTreeSha256: input.sourceTreeSha256,
          staticArtifactSha256: input.staticArtifactSha256,
          deleteServerRelease: createdServerRelease,
          deleteStaticRelease: createdStaticRelease,
        });
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          "Candidate staging failed and exact partial candidate cleanup also failed",
        );
      }
    }
    throw error;
  }
}

export function createNoBackupCandidateLifecycle(
  input: NoBackupCandidateStagingInput,
): NoBackupCandidateLifecycle {
  let owned:
    | {
      readonly server: boolean;
      readonly static: boolean;
    }
    | undefined;
  return {
    stage: async () => {
      const staged = await stageNoBackupCandidatePair(input);
      owned = {
        server: staged.createdServerRelease,
        static: staged.createdStaticRelease,
      };
      return staged.binding;
    },
    discardBeforeTransaction: async (candidate) => {
      if (candidate.releaseId !== input.releaseId) {
        throw new Error(
          "Pre-transaction cleanup candidate differs from the staged release",
        );
      }
      if (!owned?.server && !owned?.static) return;
      await discardUnpublishedNoBackupCandidate({
        releaseId: input.releaseId,
        serverReleaseRoot: input.serverReleaseRoot,
        staticReleaseRoot: input.staticReleaseRoot,
        applicationPath: input.applicationPath,
        sourceTreeSha256: input.sourceTreeSha256,
        staticArtifactSha256: input.staticArtifactSha256,
        deleteServerRelease: owned.server,
        deleteStaticRelease: owned.static,
      });
    },
  };
}

interface ParsedCandidateArguments {
  readonly command: "inspect" | "stage-deploy";
  readonly sourceRoot: string;
  readonly staticBuildRoot: string;
  readonly releaseId?: string;
  readonly confirmation?: string;
  readonly sourceCommit?: string;
  readonly sourceTreeSha256?: string;
  readonly staticArtifactSha256?: string;
}

export function parseNoBackupCandidateArguments(
  argv: readonly string[],
): ParsedCandidateArguments {
  const [command, ...rest] = argv;
  if (command !== "inspect" && command !== "stage-deploy") {
    throw new Error(
      "No-backup candidate command must be inspect or stage-deploy",
    );
  }
  const flags = new Set<string>();
  const values = new Map<string, string>();
  const allowedValues = new Set([
    "--source-root",
    "--static-build-root",
    "--release-id",
    "--confirm",
    "--source-commit",
    "--source-tree-sha256",
    "--static-artifact-sha256",
  ]);
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (
      token === "--execute" ||
      token === "--acknowledge-no-backup-risk"
    ) {
      if (flags.has(token)) {
        throw new Error(`Duplicate flag: ${token}`);
      }
      flags.add(token);
      continue;
    }
    if (!allowedValues.has(token)) {
      throw new Error(
        `Unsupported no-backup candidate option: ${token}`,
      );
    }
    if (values.has(token)) {
      throw new Error(`Duplicate option: ${token}`);
    }
    const value = rest[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`${token} requires a value`);
    }
    values.set(token, value);
    index += 1;
  }
  const sourceRoot = values.get("--source-root")?.trim() ?? "";
  const staticBuildRoot =
    values.get("--static-build-root")?.trim() ?? "";
  if (!sourceRoot || !staticBuildRoot) {
    throw new Error(
      "--source-root and --static-build-root are required",
    );
  }
  if (command === "inspect") {
    if (
      flags.size ||
      [...values.keys()].some((name) =>
        name !== "--source-root" &&
        name !== "--static-build-root")
    ) {
      throw new Error(
        "Candidate inspection accepts only the two explicit source paths",
      );
    }
    return { command, sourceRoot, staticBuildRoot };
  }
  if (
    !flags.has("--execute") ||
    !flags.has("--acknowledge-no-backup-risk")
  ) {
    throw new Error(
      "Candidate stage-deploy requires --execute and --acknowledge-no-backup-risk",
    );
  }
  const releaseId = values.get("--release-id")?.trim() ?? "";
  const confirmation = values.get("--confirm")?.trim() ?? "";
  const sourceCommit =
    values.get("--source-commit")?.trim().toLowerCase() ?? "";
  const sourceTreeSha256 =
    values.get("--source-tree-sha256")?.trim().toLowerCase() ?? "";
  const staticArtifactSha256 =
    values.get("--static-artifact-sha256")?.trim().toLowerCase() ?? "";
  if (!RELEASE_ID.test(releaseId)) {
    throw new Error("A safe --release-id is required");
  }
  if (confirmation !== releaseId) {
    throw new Error("--confirm must exactly match --release-id");
  }
  if (!GIT_COMMIT.test(sourceCommit)) {
    throw new Error("A full --source-commit is required");
  }
  if (!SHA256.test(sourceTreeSha256)) {
    throw new Error("A lowercase --source-tree-sha256 is required");
  }
  if (!SHA256.test(staticArtifactSha256)) {
    throw new Error(
      "A lowercase --static-artifact-sha256 is required",
    );
  }
  return {
    command,
    sourceRoot,
    staticBuildRoot,
    releaseId,
    confirmation,
    sourceCommit,
    sourceTreeSha256,
    staticArtifactSha256,
  };
}

export async function runNoBackupCandidateRelease(
  argv = process.argv.slice(2),
  dependencies: NoBackupCandidateCliDependencies = {},
): Promise<NoBackupCandidateCliResult> {
  const args = parseNoBackupCandidateArguments(argv);
  const inspection = await inspectNoBackupCandidateSource({
    sourceRoot: args.sourceRoot,
    staticBuildRoot: args.staticBuildRoot,
  });
  if (args.command === "inspect") {
    return { command: "inspect", inspection };
  }
  assertPins(inspection, {
    sourceCommit: args.sourceCommit!,
    sourceTreeSha256: args.sourceTreeSha256!,
    staticArtifactSha256: args.staticArtifactSha256!,
  });
  const releaseArguments = [
    "deploy",
    "--execute",
    "--release-id",
    args.releaseId!,
    "--confirm",
    args.confirmation!,
    "--acknowledge-no-backup-risk",
  ] as const;
  const lifecycle = createNoBackupCandidateLifecycle({
    releaseId: args.releaseId!,
    sourceRoot: inspection.sourceRoot,
    staticBuildRoot: inspection.staticBuildRoot,
    sourceCommit: args.sourceCommit!,
    sourceTreeSha256: args.sourceTreeSha256!,
    staticArtifactSha256: args.staticArtifactSha256!,
    serverReleaseRoot:
      dependencies.serverReleaseRoot ??
      NO_BACKUP_SERVER_RELEASE_ROOT,
    staticReleaseRoot:
      dependencies.staticReleaseRoot ??
      NO_BACKUP_STATIC_RELEASE_ROOT,
    applicationPath:
      dependencies.applicationPath ?? NO_BACKUP_APPLICATION_PATH,
  });
  const receipt = await (
    dependencies.runRelease ??
    runNoBackupPreviewReleaseWithCandidate
  )(releaseArguments, lifecycle);
  return { command: "stage-deploy", receipt };
}

export function noBackupCandidateUsage(): string {
  return [
    "Ti-Scale clean-source, forward-only candidate staging",
    "",
    "Read-only inspection:",
    "  bun run release:no-backup:inspect-candidate -- \\",
    "    --source-root /absolute/clean/checkout \\",
    "    --static-build-root /absolute/clean/checkout/dist",
    "",
    "Stage and immediately hand off under one release lock:",
    "  bun run release:no-backup:stage-deploy -- \\",
    "    --source-root /absolute/clean/checkout \\",
    "    --static-build-root /absolute/clean/checkout/dist \\",
    "    --source-commit FULL_GIT_COMMIT \\",
    "    --source-tree-sha256 SERVER_TREE_SHA256 \\",
    "    --static-artifact-sha256 STATIC_TREE_SHA256 \\",
    "    --release-id ID --confirm ID --execute \\",
    "    --acknowledge-no-backup-risk",
    "",
    "The source must be the exact clean Git worktree root and the build must be",
    "its exact dist directory. No database, source, static-pointer, Vault,",
    "snapshot, archive, or prior-state copy is created.",
    "",
  ].join("\n");
}
