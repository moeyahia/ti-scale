import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, relative, resolve, sep } from "node:path";

const EXCLUDED_SOURCE_SEGMENTS = new Set([
  ".git",
  ".vite",
  "artifacts",
  "coverage",
  "data",
  "dist",
  "node_modules",
  "playwright-report",
  "test-results",
]);

function isExcludedSourceEntry(name: string): boolean {
  if (EXCLUDED_SOURCE_SEGMENTS.has(name)) return true;
  if (name === ".env" || (name.startsWith(".env.") && name !== ".env.example")) return true;
  if (name === "core" || name.startsWith("core.")) return true;
  return /\.(?:log|sqlite|sqlite-shm|sqlite-wal)$/u.test(name);
}

export interface FileManifestEntry {
  readonly path: string;
  readonly kind: "file" | "symlink";
  readonly bytes: number;
  readonly mode: string;
  readonly sha256: string;
  readonly linkTarget?: string;
}

export interface FileManifest {
  readonly root: string;
  readonly files: number;
  readonly bytes: number;
  readonly sha256: string;
  readonly entries: readonly FileManifestEntry[];
}

export interface GitReceipt {
  readonly repositoryRoot: string;
  readonly repositoryUrl: string | null;
  readonly branch: string;
  readonly head: string;
  readonly commitTimestamp: string;
  readonly applicationPath: string;
  readonly applicationTracked: boolean;
  readonly applicationClean: boolean;
  readonly changedPathCount: number;
  readonly changedPathsSha256: string;
}

export interface ReleaseAttestation {
  readonly schemaVersion: "ti-scale.release-attestation.v1";
  readonly createdAt: string;
  readonly immutableSourceAttested: boolean;
  readonly releaseCandidateEligible: false;
  readonly signed: false;
  readonly blockers: readonly string[];
  readonly git: GitReceipt;
  readonly runtime: {
    readonly bunVersion: string;
    readonly executable: string;
    readonly executableSha256: string;
    readonly platform: NodeJS.Platform;
    readonly architecture: string;
  };
  readonly source: FileManifest;
  readonly artifact: FileManifest;
  readonly criticalHashes: {
    readonly packageJson: string;
    readonly lockfile: string;
    readonly identityMark: string;
    readonly identityWordmark: string;
    readonly migrations: string;
  };
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function normalizedRelative(root: string, path: string): string {
  return relative(root, path).split(sep).join("/");
}

function manifestDigest(entries: readonly FileManifestEntry[]): string {
  return sha256(entries.map((entry) => [
    entry.kind,
    entry.path,
    entry.bytes,
    entry.mode,
    entry.sha256,
    entry.linkTarget ?? "",
  ].join("\u0000")).join("\n"));
}

export function createFileManifest(
  root: string,
  options: { readonly excludeSourceEphemera?: boolean } = {},
): FileManifest {
  const absoluteRoot = resolve(root);
  const entries: FileManifestEntry[] = [];
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"))) {
      if (options.excludeSourceEphemera && isExcludedSourceEntry(name)) continue;
      const path = resolve(directory, name);
      const relativePath = normalizedRelative(absoluteRoot, path);
      const metadata = lstatSync(path);
      if (metadata.isDirectory()) {
        visit(path);
        continue;
      }
      if (metadata.isSymbolicLink()) {
        const linkTarget = readlinkSync(path);
        entries.push({
          path: relativePath,
          kind: "symlink",
          bytes: Buffer.byteLength(linkTarget),
          mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
          sha256: sha256(linkTarget),
          linkTarget,
        });
        continue;
      }
      if (!metadata.isFile()) continue;
      const content = readFileSync(path);
      entries.push({
        path: relativePath,
        kind: "file",
        bytes: metadata.size,
        mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
        sha256: sha256(content),
      });
    }
  };
  visit(absoluteRoot);
  entries.sort((left, right) => left.path.localeCompare(right.path, "en"));
  return {
    root: basename(absoluteRoot),
    files: entries.length,
    bytes: entries.reduce((total, entry) => total + entry.bytes, 0),
    sha256: manifestDigest(entries),
    entries,
  };
}

interface CommandResult {
  readonly stdout: string;
  readonly exitCode: number;
}

function command(commandName: string, args: readonly string[], cwd: string): CommandResult {
  const result = Bun.spawnSync([commandName, ...args], {
    cwd,
    env: process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  return {
    stdout: result.stdout.toString().trim(),
    exitCode: result.exitCode,
  };
}

function requiredCommand(commandName: string, args: readonly string[], cwd: string): string {
  const result = command(commandName, args, cwd);
  if (result.exitCode !== 0) {
    throw new Error(`${commandName} ${args.join(" ")} failed while creating release attestation`);
  }
  return result.stdout;
}

export function readGitReceipt(repositoryRoot: string, applicationRoot: string): GitReceipt {
  const appPath = normalizedRelative(repositoryRoot, applicationRoot);
  const tracked = command("git", ["ls-files", "--error-unmatch", "--", `${appPath}/package.json`], repositoryRoot);
  const changed = requiredCommand(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all", "--", appPath],
    repositoryRoot,
  ).split("\n").filter(Boolean).sort();
  const repositoryUrl = command("git", ["remote", "get-url", "origin"], repositoryRoot);
  return {
    repositoryRoot,
    repositoryUrl: repositoryUrl.exitCode === 0 && repositoryUrl.stdout ? repositoryUrl.stdout : null,
    branch: requiredCommand("git", ["branch", "--show-current"], repositoryRoot) || "DETACHED",
    head: requiredCommand("git", ["rev-parse", "HEAD"], repositoryRoot),
    commitTimestamp: requiredCommand("git", ["show", "-s", "--format=%cI", "HEAD"], repositoryRoot),
    applicationPath: appPath,
    applicationTracked: tracked.exitCode === 0,
    applicationClean: changed.length === 0,
    changedPathCount: changed.length,
    changedPathsSha256: sha256(changed.join("\n")),
  };
}

function criticalFileHash(path: string): string {
  return sha256(readFileSync(path));
}

export function buildReleaseAttestation(input: {
  readonly repositoryRoot: string;
  readonly applicationRoot: string;
  readonly artifactRoot: string;
  readonly createdAt?: string;
}): ReleaseAttestation {
  const git = readGitReceipt(input.repositoryRoot, input.applicationRoot);
  const source = createFileManifest(input.applicationRoot, { excludeSourceEphemera: true });
  const artifact = createFileManifest(input.artifactRoot);
  const migrations = createFileManifest(resolve(input.applicationRoot, "server/db/migrations"));
  const bunExecutable = process.execPath;
  const blockers: string[] = [];
  if (!git.applicationTracked) blockers.push("The V2 application package is not present in the pinned Git revision");
  if (!git.applicationClean) blockers.push("The V2 application worktree differs from the pinned Git revision");
  if (artifact.files === 0) blockers.push("The production artifact manifest is empty");
  blockers.push("This local digest is unsigned and does not include release-gate, soak, preview, rollback, or human approval");
  const immutableSourceAttested = git.applicationTracked && git.applicationClean && artifact.files > 0;
  return {
    schemaVersion: "ti-scale.release-attestation.v1",
    createdAt: input.createdAt ?? new Date().toISOString(),
    immutableSourceAttested,
    releaseCandidateEligible: false,
    signed: false,
    blockers,
    git,
    runtime: {
      bunVersion: Bun.version,
      executable: bunExecutable,
      executableSha256: criticalFileHash(bunExecutable),
      platform: process.platform,
      architecture: process.arch,
    },
    source,
    artifact,
    criticalHashes: {
      packageJson: criticalFileHash(resolve(input.applicationRoot, "package.json")),
      lockfile: criticalFileHash(resolve(input.applicationRoot, "bun.lock")),
      identityMark: criticalFileHash(resolve(input.applicationRoot, "public/brand-v2/source/ti-scale-mark.svg")),
      identityWordmark: criticalFileHash(resolve(input.applicationRoot, "public/brand-v2/source/ti-scale-wordmark.svg")),
      migrations: migrations.sha256,
    },
  };
}

export function writeAttestationAtomically(path: string, attestation: ReleaseAttestation): void {
  const destination = resolve(path);
  mkdirSync(resolve(destination, ".."), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(attestation, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    renameSync(temporary, destination);
  } finally {
    rmSync(temporary, { force: true });
  }
}

async function main(): Promise<void> {
  const applicationRoot = resolve(import.meta.dir, "..");
  const repositoryRoot = requiredCommand("git", ["rev-parse", "--show-toplevel"], applicationRoot);
  const outputFlag = process.argv.indexOf("--output");
  const output = outputFlag >= 0 && process.argv[outputFlag + 1]
    ? resolve(process.cwd(), process.argv[outputFlag + 1]!)
    : resolve(applicationRoot, "test-results/attestations/ti-scale-release-attestation.json");
  const attestation = buildReleaseAttestation({
    repositoryRoot,
    applicationRoot,
    artifactRoot: resolve(applicationRoot, "dist"),
  });
  writeAttestationAtomically(output, attestation);
  console.log(JSON.stringify({
    output,
    immutableSourceAttested: attestation.immutableSourceAttested,
    releaseCandidateEligible: attestation.releaseCandidateEligible,
    sourceManifest: attestation.source.sha256,
    artifactManifest: attestation.artifact.sha256,
    blockers: attestation.blockers,
  }, null, 2));
  if (!attestation.immutableSourceAttested && !process.argv.includes("--allow-ineligible")) process.exitCode = 1;
}

if (import.meta.main) await main();
