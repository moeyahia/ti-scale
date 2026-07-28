import { randomBytes, randomUUID } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { canonicalJson, deepFreeze, hashCanonical, sha256, type JsonValue } from "./canonical";
import {
  type LabReceiptSubject,
  type ResearchExecutionBindings,
  type ResearchExecutionReceipt,
  ResearchExecutionReceiptKeyring,
} from "./ResearchExecutionReceipts";

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const OWNED_DIRECTORY = /^lab-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MARKER_FILE = ".ti-scale-owned.json";
const DIRTY_FILE = ".ti-scale-reset-challenge";
const MAXIMUM_FIXTURE_FILES = 256;
const MAXIMUM_FIXTURE_BYTES = 4 * 1024 * 1024;

export interface SyntheticBenchmarkFixture {
  readonly scenarioId: string;
  readonly targetClass: "synthetic_fixture";
  readonly files: Readonly<Record<string, string>>;
  readonly environmentDigest: string;
}

export interface PrepareLabInput extends ResearchExecutionBindings {
  readonly fixture: SyntheticBenchmarkFixture;
}

export interface PreparedLabEnvironment {
  readonly workspacePath: string;
  readonly baselineStateHash: string;
  readonly resetGeneration: string;
  readonly receipt: ResearchExecutionReceipt<"lab">;
  dispose(): boolean;
}

interface OwnedMarker {
  readonly schemaVersion: "ti-scale.research-lab-workspace.v1";
  readonly application: "ti-scale";
  readonly createdByUid: number;
  readonly bootId: string;
}

function currentUid(): number {
  return process.geteuid?.() ?? process.getuid?.() ?? 0;
}

function currentGid(): number {
  return process.getegid?.() ?? process.getgid?.() ?? 0;
}

function safeRoot(value: string): string {
  const root = resolve(value);
  if (!isAbsolute(root) || root === resolve(sep) || CONTROL_CHARACTERS.test(root)) {
    throw new Error("Research lab temporary root is unsafe.");
  }
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const pathMetadata = lstatSync(root);
  if (
    pathMetadata.isSymbolicLink()
    || !pathMetadata.isDirectory()
    || (pathMetadata.mode & 0o077) !== 0
    || (pathMetadata.uid !== 0 && pathMetadata.uid !== currentUid())
  ) {
    throw new Error("Research lab temporary root must be a private owned directory.");
  }
  return root;
}

function safeFixturePath(value: string): string {
  if (
    value.length < 1
    || value.length > 240
    || value.includes("\\")
    || CONTROL_CHARACTERS.test(value)
    || isAbsolute(value)
  ) throw new Error("Synthetic fixture contains an unsafe path.");
  const normalized = value.split("/").filter(Boolean).join("/");
  if (
    normalized !== value
    || normalized === MARKER_FILE
    || normalized === DIRTY_FILE
    || normalized.split("/").some((segment) =>
      segment === "." || segment === ".." || segment.length === 0)
  ) throw new Error("Synthetic fixture contains an unsafe path.");
  return normalized;
}

function normalizedFixtureFiles(
  files: Readonly<Record<string, string>>,
): Readonly<Record<string, string>> {
  const entries = Object.entries(files)
    .map(([path, content]) => {
      if (typeof content !== "string") {
        throw new Error("Synthetic fixture content must be UTF-8 text.");
      }
      return [safeFixturePath(path), content] as const;
    })
    .sort(([left], [right]) => left.localeCompare(right));
  if (entries.length < 1 || entries.length > MAXIMUM_FIXTURE_FILES) {
    throw new Error("Synthetic fixture file count is outside the reviewed bound.");
  }
  const totalBytes = entries.reduce(
    (total, [, content]) => total + Buffer.byteLength(content, "utf8"),
    0,
  );
  if (totalBytes > MAXIMUM_FIXTURE_BYTES) {
    throw new Error("Synthetic fixture content exceeds the reviewed byte bound.");
  }
  if (new Set(entries.map(([path]) => path)).size !== entries.length) {
    throw new Error("Synthetic fixture repeats a normalized path.");
  }
  return Object.freeze(Object.fromEntries(entries));
}

export function syntheticFixtureEnvironmentDigest(
  files: Readonly<Record<string, string>>,
): string {
  const normalized = normalizedFixtureFiles(files);
  return `sha256:${hashCanonical(
    Object.entries(normalized) as unknown as JsonValue,
  )}`;
}

function fixtureStateHash(files: Readonly<Record<string, string>>): string {
  return hashCanonical(
    Object.entries(files)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([path, content]) => [path, sha256(content)]) as unknown as JsonValue,
  );
}

function walkFiles(root: string, current = root): Array<readonly [string, string]> {
  const result: Array<readonly [string, string]> = [];
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const absolute = join(current, entry.name);
    const childRelative = relative(root, absolute).split(sep).join("/");
    if (entry.isSymbolicLink()) {
      throw new Error("Research lab workspace contains a symbolic link.");
    }
    if (entry.isDirectory()) {
      result.push(...walkFiles(root, absolute));
      continue;
    }
    if (!entry.isFile()) {
      throw new Error("Research lab workspace contains a non-regular entry.");
    }
    if (childRelative === MARKER_FILE) continue;
    const source = readFileSync(absolute);
    result.push([childRelative, sha256(source)]);
  }
  return result.sort(([left], [right]) => left.localeCompare(right));
}

function workspaceStateHash(root: string): string {
  return hashCanonical(walkFiles(root) as unknown as JsonValue);
}

function writeMarker(root: string, marker: OwnedMarker): void {
  writeFileSync(
    join(root, MARKER_FILE),
    `${canonicalJson(marker as unknown as JsonValue)}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
}

function materialize(
  workspace: string,
  files: Readonly<Record<string, string>>,
  marker: OwnedMarker,
): void {
  mkdirSync(workspace, { recursive: false, mode: 0o700 });
  writeMarker(workspace, marker);
  for (const [relativePath, content] of Object.entries(files)) {
    const absolute = join(workspace, relativePath);
    const parent = resolve(absolute, "..");
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    const rel = relative(workspace, absolute);
    if (rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel)) {
      throw new Error("Synthetic fixture escaped its disposable workspace.");
    }
    writeFileSync(absolute, content, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
  }
}

function readMarker(path: string): OwnedMarker | undefined {
  const markerPath = join(path, MARKER_FILE);
  if (!existsSync(markerPath)) return undefined;
  const metadata = lstatSync(markerPath);
  if (
    metadata.isSymbolicLink()
    || !metadata.isFile()
    || metadata.uid !== currentUid()
    || (metadata.mode & 0o077) !== 0
    || metadata.size > 2_048
  ) return undefined;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      markerPath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const value = JSON.parse(readFileSync(descriptor, "utf8")) as OwnedMarker;
    return value.schemaVersion === "ti-scale.research-lab-workspace.v1"
      && value.application === "ti-scale"
      && value.createdByUid === currentUid()
      && typeof value.bootId === "string"
      ? value
      : undefined;
  } catch {
    return undefined;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

/**
 * Owns only generated synthetic fixture directories. Reset is destructive
 * recreation from an immutable typed fixture, never a filesystem snapshot,
 * database backup, archive, or copied client environment.
 */
export class LabEnvironmentManager {
  readonly temporaryRoot: string;
  readonly #keyring: ResearchExecutionReceiptKeyring;

  constructor(
    temporaryRoot: string,
    keyring: ResearchExecutionReceiptKeyring,
  ) {
    this.temporaryRoot = safeRoot(temporaryRoot);
    this.#keyring = keyring;
    this.sweepOwnedStaleWorkspaces();
  }

  sweepOwnedStaleWorkspaces(): number {
    let removed = 0;
    for (const entry of readdirSync(this.temporaryRoot, { withFileTypes: true })) {
      if (!OWNED_DIRECTORY.test(entry.name) || !entry.isDirectory()) continue;
      const candidate = join(this.temporaryRoot, entry.name);
      const metadata = lstatSync(candidate);
      if (
        metadata.isSymbolicLink()
        || metadata.uid !== currentUid()
        || !readMarker(candidate)
      ) continue;
      rmSync(candidate, { recursive: true, force: true });
      if (!existsSync(candidate)) removed += 1;
    }
    return removed;
  }

  prepare(input: PrepareLabInput): PreparedLabEnvironment {
    if (
      input.fixture.targetClass !== "synthetic_fixture"
      || input.fixture.scenarioId !== input.scenarioId
    ) {
      throw new Error("Research lab accepts only the exact synthetic benchmark scenario.");
    }
    const files = normalizedFixtureFiles(input.fixture.files);
    const calculatedDigest = syntheticFixtureEnvironmentDigest(files);
    if (input.fixture.environmentDigest !== calculatedDigest) {
      throw new Error("Synthetic benchmark environment digest does not match its immutable fixture.");
    }
    const expectedBaselineHash = fixtureStateHash(files);
    const workspace = join(this.temporaryRoot, `lab-${randomUUID()}`);
    const marker: OwnedMarker = {
      schemaVersion: "ti-scale.research-lab-workspace.v1",
      application: "ti-scale",
      createdByUid: currentUid(),
      bootId: this.#keyring.bootId,
    };
    let disposed = false;
    try {
      materialize(workspace, files, marker);
      const initialStateHash = workspaceStateHash(workspace);
      if (initialStateHash !== expectedBaselineHash) {
        throw new Error("Synthetic fixture did not materialize to its immutable baseline.");
      }
      writeFileSync(
        join(workspace, DIRTY_FILE),
        randomBytes(32),
        { flag: "wx", mode: 0o600 },
      );
      const dirtyStateHash = workspaceStateHash(workspace);
      if (dirtyStateHash === expectedBaselineHash) {
        throw new Error("Synthetic fixture dirty-state challenge did not change the environment.");
      }

      // Reset is deliberate full recreation from typed fixture values. No
      // snapshot, backup, archive, or source-directory copy exists.
      rmSync(workspace, { recursive: true, force: false });
      materialize(workspace, files, marker);
      const resetStateHash = workspaceStateHash(workspace);
      if (
        resetStateHash !== expectedBaselineHash
        || existsSync(join(workspace, DIRTY_FILE))
      ) {
        throw new Error("Synthetic fixture failed its dirty-to-baseline reset challenge.");
      }
      const resetGeneration = hashCanonical({
        bootId: this.#keyring.bootId,
        experimentId: input.experimentId,
        scenarioId: input.scenarioId,
        resetNonce: randomBytes(32).toString("hex"),
        resetStateHash,
      } as unknown as JsonValue);
      const challengeHash = sha256(randomBytes(32).toString("hex"));
      const subject: LabReceiptSubject = {
        environmentDigest: calculatedDigest,
        baselineStateHash: expectedBaselineHash,
        dirtyStateHash,
        resetStateHash,
        workspacePathHash: sha256(workspace),
        resetMode: "recreate",
        ownerUid: currentUid(),
        ownerGid: currentGid(),
      };
      const subjectIdentityHash = hashCanonical(subject as unknown as JsonValue);
      const evidenceHash = hashCanonical({
        challengeHash,
        subjectIdentityHash,
        initialStateHash,
        dirtyStateHash,
        resetStateHash,
      } as unknown as JsonValue);
      const receipt = this.#keyring.create("lab", {
        experimentId: input.experimentId,
        scenarioId: input.scenarioId,
        benchmarkSnapshotHash: input.benchmarkSnapshotHash,
        evaluatorHash: input.evaluatorHash,
        toolManifestHash: input.toolManifestHash,
        resetGeneration,
        challengeHash,
        subjectIdentityHash,
        evidenceHash,
        controls: {
          liveClientTargetsAllowed: false,
          productionSecretsMounted: false,
          productionMutationAllowed: false,
          publicProviderExecutionAllowed: false,
          quotaBound: true,
          resetVerified: true,
        },
        subject,
      });
      return deepFreeze({
        workspacePath: workspace,
        baselineStateHash: expectedBaselineHash,
        resetGeneration,
        receipt,
        dispose(): boolean {
          if (disposed) return true;
          disposed = true;
          rmSync(workspace, { recursive: true, force: true });
          return !existsSync(workspace);
        },
      });
    } catch (error) {
      rmSync(workspace, { recursive: true, force: true });
      throw error;
    }
  }
}
