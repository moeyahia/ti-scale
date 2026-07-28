import { createHash, createPublicKey, verify } from "node:crypto";
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
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { runBoundedReleaseCommand } from "./release/BoundedReleaseCommand";

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_RELEASE_INPUT_BYTES = 1024 * 1024;
const GIT_COMMAND_TIMEOUT_MS = 30_000;
const GIT_COMMAND_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024;

export const RELEASE_GATE_IDS = [
  "source-build-integrity",
  "runtime-truth",
  "interaction-completeness",
  "browser-visual-quality",
  "data-evidence-memory",
  "research-safety",
  "performance-reliability",
  "deployment-approval",
] as const;

export type ReleaseGateId = typeof RELEASE_GATE_IDS[number];

const EXCLUDED_SOURCE_SEGMENTS = new Set([
  ".artifacts",
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

export interface ReleaseEvidenceArtifact {
  readonly path: string;
  readonly sha256: string;
}

export interface ReleaseGateEvidence {
  readonly gate: ReleaseGateId;
  readonly status: "passed";
  readonly completedAt: string;
  readonly artifacts: readonly ReleaseEvidenceArtifact[];
}

export interface ReleaseEvidenceBundle {
  readonly schemaVersion: "ti-scale.release-evidence.v1";
  readonly releaseId: string;
  readonly gitHead: string;
  readonly sourceManifestSha256: string;
  readonly artifactManifestSha256: string;
  readonly knownGapCount: 0;
  readonly openReleaseScopeDefectCount: 0;
  readonly skippedTestCount: 0;
  readonly quarantinedTestCount: 0;
  readonly retryMaskedTestCount: 0;
  readonly gates: readonly ReleaseGateEvidence[];
}

export interface ReleaseSignOffPayload {
  readonly schemaVersion: "ti-scale.release-sign-off.v1";
  readonly releaseId: string;
  readonly decision: "approved";
  readonly approvedBy: string;
  readonly approvedAt: string;
  readonly gitHead: string;
  readonly sourceManifestSha256: string;
  readonly artifactManifestSha256: string;
  readonly evidenceBundleSha256: string;
  readonly signatureAlgorithm: "ed25519";
}

export interface ReleaseSignOff extends ReleaseSignOffPayload {
  readonly signatureBase64: string;
}

export interface ReleaseEvidenceReceipt {
  readonly status: "not-supplied" | "invalid" | "validated";
  readonly path: string | null;
  readonly sha256: string | null;
  readonly releaseId: string | null;
  readonly validatedGateCount: number;
}

export interface ReleaseSignOffReceipt {
  readonly status: "not-supplied" | "invalid" | "verified";
  readonly path: string | null;
  readonly sha256: string | null;
  readonly approvedBy: string | null;
  readonly approvedAt: string | null;
  readonly trustedPublicKeySha256: string | null;
}

export interface InteractionManifestGapReceipt {
  readonly status: "invalid" | "validated";
  readonly path: string;
  readonly sha256: string | null;
  readonly knownGapCount: number | null;
}

export interface ReleaseAttestation {
  readonly schemaVersion: "ti-scale.release-attestation.v1";
  readonly createdAt: string;
  readonly immutableSourceAttested: boolean;
  readonly releaseCandidateEligible: boolean;
  readonly signed: boolean;
  readonly blockers: readonly string[];
  readonly interactionManifest: InteractionManifestGapReceipt;
  readonly releaseEvidence: ReleaseEvidenceReceipt;
  readonly humanSignOff: ReleaseSignOffReceipt;
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

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} fields must be exactly: ${wanted.join(", ")}`);
  }
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function requiredSha256(value: unknown, label: string): string {
  const digest = requiredString(value, label);
  if (!SHA256_PATTERN.test(digest)) throw new Error(`${label} must be a lowercase SHA-256 digest`);
  return digest;
}

function requiredGitHead(value: unknown, label: string): string {
  const digest = requiredString(value, label);
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(digest)) {
    throw new Error(`${label} must be a lowercase Git object ID`);
  }
  return digest;
}

function requiredIsoTimestamp(value: unknown, label: string): string {
  const timestamp = requiredString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u.test(timestamp)
    || !Number.isFinite(Date.parse(timestamp))) {
    throw new Error(`${label} must be an ISO-8601 timestamp with an explicit offset`);
  }
  return timestamp;
}

function requiredZero(value: unknown, label: string): 0 {
  if (value !== 0) throw new Error(`${label} must be zero`);
  return 0;
}

function readBoundedRegularFile(path: string, label: string): { readonly path: string; readonly bytes: Buffer } {
  const absolutePath = resolve(path);
  const metadata = lstatSync(absolutePath);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`${label} must be a regular file, not a symlink`);
  if (metadata.size <= 0 || metadata.size > MAX_RELEASE_INPUT_BYTES) {
    throw new Error(`${label} must contain between 1 and ${MAX_RELEASE_INPUT_BYTES} bytes`);
  }
  return { path: absolutePath, bytes: readFileSync(absolutePath) };
}

function readBoundedJson(path: string, label: string): {
  readonly path: string;
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly value: Record<string, unknown>;
} {
  const file = readBoundedRegularFile(path, label);
  let parsed: unknown;
  try {
    parsed = JSON.parse(file.bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} must contain valid JSON`);
  }
  return { ...file, sha256: sha256(file.bytes), value: object(parsed, label) };
}

function readInteractionManifestGapReceipt(applicationRoot: string): InteractionManifestGapReceipt {
  const path = resolve(applicationRoot, "tests/interaction-manifest.json");
  const input = readBoundedJson(path, "Interaction manifest");
  if (!Array.isArray(input.value.knownGaps)) throw new Error("Interaction manifest knownGaps must be an array");
  const normalized = input.value.knownGaps.map((gap, index) => requiredString(gap, `Interaction manifest knownGaps[${index}]`).trim());
  if (new Set(normalized).size !== normalized.length) throw new Error("Interaction manifest knownGaps must not contain duplicates");
  return { status: "validated", path: input.path, sha256: input.sha256, knownGapCount: normalized.length };
}

function evidenceArtifactPath(bundlePath: string, value: unknown, label: string): string {
  const path = requiredString(value, label);
  if (isAbsolute(path) || path.includes("\0")) throw new Error(`${label} must be a safe relative path`);
  const root = dirname(bundlePath);
  const absolutePath = resolve(root, path);
  const relativePath = relative(root, absolutePath);
  if (!relativePath || relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new Error(`${label} must remain inside the evidence bundle directory`);
  }
  return absolutePath;
}

interface ValidatedReleaseEvidence {
  readonly bundle: ReleaseEvidenceBundle;
  readonly path: string;
  readonly sha256: string;
  readonly latestGateCompletion: number;
}

function validateReleaseEvidence(
  path: string,
  expected: {
    readonly gitHead: string;
    readonly sourceManifestSha256: string;
    readonly artifactManifestSha256: string;
    readonly interactionManifestKnownGapCount: number;
    readonly attestationCreatedAt: string;
  },
): ValidatedReleaseEvidence {
  const input = readBoundedJson(path, "Release evidence bundle");
  exactKeys(input.value, [
    "schemaVersion", "releaseId", "gitHead", "sourceManifestSha256", "artifactManifestSha256",
    "knownGapCount", "openReleaseScopeDefectCount", "skippedTestCount", "quarantinedTestCount",
    "retryMaskedTestCount", "gates",
  ], "Release evidence bundle");
  if (input.value.schemaVersion !== "ti-scale.release-evidence.v1") {
    throw new Error("Release evidence bundle schemaVersion is unsupported");
  }
  const releaseId = requiredString(input.value.releaseId, "Release evidence releaseId");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(releaseId)) {
    throw new Error("Release evidence releaseId has an invalid format");
  }
  const gitHead = requiredGitHead(input.value.gitHead, "Release evidence gitHead");
  const sourceManifestSha256 = requiredSha256(input.value.sourceManifestSha256, "Release evidence sourceManifestSha256");
  const artifactManifestSha256 = requiredSha256(input.value.artifactManifestSha256, "Release evidence artifactManifestSha256");
  if (gitHead !== expected.gitHead) throw new Error("Release evidence does not match the attested Git HEAD");
  if (sourceManifestSha256 !== expected.sourceManifestSha256) {
    throw new Error("Release evidence does not match the attested source manifest");
  }
  if (artifactManifestSha256 !== expected.artifactManifestSha256) {
    throw new Error("Release evidence does not match the attested artifact manifest");
  }
  const knownGapCount = requiredZero(input.value.knownGapCount, "Release evidence knownGapCount");
  if (knownGapCount !== expected.interactionManifestKnownGapCount) {
    throw new Error("Release evidence knownGapCount does not match the attested interaction manifest");
  }
  const openReleaseScopeDefectCount = requiredZero(input.value.openReleaseScopeDefectCount, "Release evidence openReleaseScopeDefectCount");
  const skippedTestCount = requiredZero(input.value.skippedTestCount, "Release evidence skippedTestCount");
  const quarantinedTestCount = requiredZero(input.value.quarantinedTestCount, "Release evidence quarantinedTestCount");
  const retryMaskedTestCount = requiredZero(input.value.retryMaskedTestCount, "Release evidence retryMaskedTestCount");
  if (!Array.isArray(input.value.gates) || input.value.gates.length !== RELEASE_GATE_IDS.length) {
    throw new Error(`Release evidence must contain exactly ${RELEASE_GATE_IDS.length} gate records`);
  }

  const gates: ReleaseGateEvidence[] = [];
  const seenGates = new Set<string>();
  const seenArtifacts = new Set<string>();
  const attestationCreatedAt = Date.parse(expected.attestationCreatedAt);
  let latestGateCompletion = Number.NEGATIVE_INFINITY;
  input.value.gates.forEach((candidate, gateIndex) => {
    const gate = object(candidate, `Release gate ${gateIndex + 1}`);
    exactKeys(gate, ["gate", "status", "completedAt", "artifacts"], `Release gate ${gateIndex + 1}`);
    const gateId = requiredString(gate.gate, `Release gate ${gateIndex + 1} gate`);
    if (!RELEASE_GATE_IDS.includes(gateId as ReleaseGateId)) throw new Error(`Unknown release gate ${gateId}`);
    if (seenGates.has(gateId)) throw new Error(`Release gate ${gateId} is duplicated`);
    seenGates.add(gateId);
    if (gate.status !== "passed") throw new Error(`Release gate ${gateId} must have passed`);
    const completedAt = requiredIsoTimestamp(gate.completedAt, `Release gate ${gateId} completedAt`);
    const completedAtEpoch = Date.parse(completedAt);
    if (completedAtEpoch > attestationCreatedAt) throw new Error(`Release gate ${gateId} completion is after the attestation time`);
    latestGateCompletion = Math.max(latestGateCompletion, completedAtEpoch);
    if (!Array.isArray(gate.artifacts) || gate.artifacts.length === 0) {
      throw new Error(`Release gate ${gateId} must reference at least one evidence artifact`);
    }
    const artifacts = gate.artifacts.map((candidateArtifact, artifactIndex): ReleaseEvidenceArtifact => {
      const artifact = object(candidateArtifact, `Release gate ${gateId} artifact ${artifactIndex + 1}`);
      exactKeys(artifact, ["path", "sha256"], `Release gate ${gateId} artifact ${artifactIndex + 1}`);
      const absolutePath = evidenceArtifactPath(input.path, artifact.path, `Release gate ${gateId} artifact path`);
      if (seenArtifacts.has(absolutePath)) throw new Error(`Release evidence artifact is reused across gates: ${artifact.path}`);
      seenArtifacts.add(absolutePath);
      const expectedSha256 = requiredSha256(artifact.sha256, `Release gate ${gateId} artifact sha256`);
      const actual = readBoundedRegularFile(absolutePath, `Release gate ${gateId} artifact`);
      if (sha256(actual.bytes) !== expectedSha256) throw new Error(`Release gate ${gateId} artifact checksum does not match`);
      return { path: requiredString(artifact.path, `Release gate ${gateId} artifact path`), sha256: expectedSha256 };
    });
    gates.push({ gate: gateId as ReleaseGateId, status: "passed", completedAt, artifacts });
  });
  if (RELEASE_GATE_IDS.some((gate) => !seenGates.has(gate))) throw new Error("Release evidence omits one or more required gates");

  return {
    path: input.path,
    sha256: input.sha256,
    latestGateCompletion,
    bundle: {
      schemaVersion: "ti-scale.release-evidence.v1",
      releaseId,
      gitHead,
      sourceManifestSha256,
      artifactManifestSha256,
      knownGapCount,
      openReleaseScopeDefectCount,
      skippedTestCount,
      quarantinedTestCount,
      retryMaskedTestCount,
      gates,
    },
  };
}

export function canonicalReleaseSignOffPayload(value: ReleaseSignOffPayload): Buffer {
  return Buffer.from(JSON.stringify({
    schemaVersion: value.schemaVersion,
    releaseId: value.releaseId,
    decision: value.decision,
    approvedBy: value.approvedBy,
    approvedAt: value.approvedAt,
    gitHead: value.gitHead,
    sourceManifestSha256: value.sourceManifestSha256,
    artifactManifestSha256: value.artifactManifestSha256,
    evidenceBundleSha256: value.evidenceBundleSha256,
    signatureAlgorithm: value.signatureAlgorithm,
  }), "utf8");
}

interface ValidatedReleaseSignOff {
  readonly signOff: ReleaseSignOff;
  readonly path: string;
  readonly sha256: string;
  readonly trustedPublicKeySha256: string;
}

function validateReleaseSignOff(
  path: string,
  trustedPublicKeyPath: string,
  evidence: ValidatedReleaseEvidence,
  expected: {
    readonly gitHead: string;
    readonly sourceManifestSha256: string;
    readonly artifactManifestSha256: string;
    readonly attestationCreatedAt: string;
  },
): ValidatedReleaseSignOff {
  const input = readBoundedJson(path, "Human release sign-off");
  exactKeys(input.value, [
    "schemaVersion", "releaseId", "decision", "approvedBy", "approvedAt", "gitHead",
    "sourceManifestSha256", "artifactManifestSha256", "evidenceBundleSha256",
    "signatureAlgorithm", "signatureBase64",
  ], "Human release sign-off");
  if (input.value.schemaVersion !== "ti-scale.release-sign-off.v1") throw new Error("Human release sign-off schemaVersion is unsupported");
  if (input.value.decision !== "approved") throw new Error("Human release sign-off decision must be approved");
  if (input.value.signatureAlgorithm !== "ed25519") throw new Error("Human release sign-off must use Ed25519");
  const releaseId = requiredString(input.value.releaseId, "Human release sign-off releaseId");
  const approvedBy = requiredString(input.value.approvedBy, "Human release sign-off approvedBy");
  const approvedAt = requiredIsoTimestamp(input.value.approvedAt, "Human release sign-off approvedAt");
  const gitHead = requiredGitHead(input.value.gitHead, "Human release sign-off gitHead");
  const sourceManifestSha256 = requiredSha256(input.value.sourceManifestSha256, "Human release sign-off sourceManifestSha256");
  const artifactManifestSha256 = requiredSha256(input.value.artifactManifestSha256, "Human release sign-off artifactManifestSha256");
  const evidenceBundleSha256 = requiredSha256(input.value.evidenceBundleSha256, "Human release sign-off evidenceBundleSha256");
  if (releaseId !== evidence.bundle.releaseId) throw new Error("Human release sign-off does not match the evidence releaseId");
  if (gitHead !== expected.gitHead) throw new Error("Human release sign-off does not match the attested Git HEAD");
  if (sourceManifestSha256 !== expected.sourceManifestSha256) throw new Error("Human release sign-off does not match the source manifest");
  if (artifactManifestSha256 !== expected.artifactManifestSha256) throw new Error("Human release sign-off does not match the artifact manifest");
  if (evidenceBundleSha256 !== evidence.sha256) throw new Error("Human release sign-off does not match the evidence bundle");
  const approvedAtEpoch = Date.parse(approvedAt);
  if (approvedAtEpoch < evidence.latestGateCompletion) throw new Error("Human release sign-off predates completed gate evidence");
  if (approvedAtEpoch > Date.parse(expected.attestationCreatedAt)) throw new Error("Human release sign-off is after the attestation time");

  const signatureBase64 = requiredString(input.value.signatureBase64, "Human release sign-off signatureBase64");
  const signature = Buffer.from(signatureBase64, "base64");
  if (signature.length !== 64 || signature.toString("base64") !== signatureBase64) {
    throw new Error("Human release sign-off signatureBase64 is not a canonical Ed25519 signature");
  }
  const publicKeyFile = readBoundedRegularFile(trustedPublicKeyPath, "Trusted human release public key");
  const publicKey = createPublicKey(publicKeyFile.bytes);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Trusted human release public key must be Ed25519");
  const signOff: ReleaseSignOff = {
    schemaVersion: "ti-scale.release-sign-off.v1",
    releaseId,
    decision: "approved",
    approvedBy,
    approvedAt,
    gitHead,
    sourceManifestSha256,
    artifactManifestSha256,
    evidenceBundleSha256,
    signatureAlgorithm: "ed25519",
    signatureBase64,
  };
  if (!verify(null, canonicalReleaseSignOffPayload(signOff), publicKey, signature)) {
    throw new Error("Human release sign-off signature verification failed");
  }
  return {
    signOff,
    path: input.path,
    sha256: input.sha256,
    trustedPublicKeySha256: sha256(publicKeyFile.bytes),
  };
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

async function command(commandName: string, args: readonly string[], cwd: string): Promise<CommandResult> {
  const result = await runBoundedReleaseCommand([commandName, ...args], {
    timeoutMs: GIT_COMMAND_TIMEOUT_MS,
    outputLimitBytes: GIT_COMMAND_OUTPUT_LIMIT_BYTES,
    allowNonZeroExit: true,
    cwd,
    env: {
      PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      HOME: process.env.HOME ?? "/root",
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_PAGER: "cat",
      GIT_TERMINAL_PROMPT: "0",
      NO_COLOR: "1",
    },
  });
  return {
    stdout: result.stdout,
    exitCode: result.exitCode,
  };
}

async function requiredCommand(commandName: string, args: readonly string[], cwd: string): Promise<string> {
  const result = await command(commandName, args, cwd);
  if (result.exitCode !== 0) {
    throw new Error(`${commandName} ${args.join(" ")} failed while creating release attestation`);
  }
  return result.stdout;
}

export async function readGitReceipt(repositoryRoot: string, applicationRoot: string): Promise<GitReceipt> {
  // Ti-Scale is a standalone repository, so the application root normally is
  // the repository root. Git rejects an empty pathspec after `--`; represent
  // that root explicitly as `.` so the attestation remains usable for both a
  // standalone checkout and a nested application checkout.
  const appPath = normalizedRelative(repositoryRoot, applicationRoot) || ".";
  const tracked = await command("/usr/bin/git", ["ls-files", "--error-unmatch", "--", `${appPath}/package.json`], repositoryRoot);
  const changed = (await requiredCommand(
    "/usr/bin/git",
    ["status", "--porcelain=v1", "--untracked-files=all", "--", appPath],
    repositoryRoot,
  )).split("\n").filter(Boolean).sort();
  const repositoryUrl = await command("/usr/bin/git", ["remote", "get-url", "origin"], repositoryRoot);
  return {
    repositoryRoot,
    repositoryUrl: repositoryUrl.exitCode === 0 && repositoryUrl.stdout ? repositoryUrl.stdout : null,
    branch: await requiredCommand("/usr/bin/git", ["branch", "--show-current"], repositoryRoot) || "DETACHED",
    head: await requiredCommand("/usr/bin/git", ["rev-parse", "HEAD"], repositoryRoot),
    commitTimestamp: await requiredCommand("/usr/bin/git", ["show", "-s", "--format=%cI", "HEAD"], repositoryRoot),
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

export async function buildReleaseAttestation(input: {
  readonly repositoryRoot: string;
  readonly applicationRoot: string;
  readonly artifactRoot: string;
  readonly createdAt?: string;
  readonly releaseEvidencePath?: string;
  readonly humanSignOffPath?: string;
  readonly trustedSignOffPublicKeyPath?: string;
}): Promise<ReleaseAttestation> {
  const createdAt = input.createdAt ?? new Date().toISOString();
  requiredIsoTimestamp(createdAt, "Release attestation createdAt");
  const git = await readGitReceipt(input.repositoryRoot, input.applicationRoot);
  const source = createFileManifest(input.applicationRoot, { excludeSourceEphemera: true });
  const artifact = createFileManifest(input.artifactRoot);
  const migrations = createFileManifest(resolve(input.applicationRoot, "server/db/migrations"));
  const bunExecutable = process.execPath;
  const blockers: string[] = [];
  if (!git.applicationTracked) blockers.push("The V2 application package is not present in the pinned Git revision");
  if (!git.applicationClean) blockers.push("The V2 application worktree differs from the pinned Git revision");
  if (artifact.files === 0) blockers.push("The production artifact manifest is empty");
  const immutableSourceAttested = git.applicationTracked && git.applicationClean && artifact.files > 0;

  let interactionManifest: InteractionManifestGapReceipt;
  try {
    interactionManifest = readInteractionManifestGapReceipt(input.applicationRoot);
    if (interactionManifest.knownGapCount !== 0) {
      blockers.push(`The interaction manifest still declares ${interactionManifest.knownGapCount} known release gap(s)`);
    }
  } catch (error) {
    interactionManifest = {
      status: "invalid",
      path: resolve(input.applicationRoot, "tests/interaction-manifest.json"),
      sha256: null,
      knownGapCount: null,
    };
    blockers.push(`Interaction manifest gap validation failed: ${error instanceof Error ? error.message : "unknown validation error"}`);
  }

  let validatedEvidence: ValidatedReleaseEvidence | undefined;
  let releaseEvidence: ReleaseEvidenceReceipt = {
    status: "not-supplied",
    path: null,
    sha256: null,
    releaseId: null,
    validatedGateCount: 0,
  };
  if (!input.releaseEvidencePath) {
    blockers.push("No checksum-verified release-gate evidence bundle was supplied");
  } else if (interactionManifest.status !== "validated" || interactionManifest.knownGapCount === null) {
    releaseEvidence = {
      status: "invalid",
      path: resolve(input.releaseEvidencePath),
      sha256: null,
      releaseId: null,
      validatedGateCount: 0,
    };
    blockers.push("Release-gate evidence cannot be validated until the interaction manifest is valid");
  } else {
    const evidencePath = resolve(input.releaseEvidencePath);
    try {
      validatedEvidence = validateReleaseEvidence(evidencePath, {
        gitHead: git.head,
        sourceManifestSha256: source.sha256,
        artifactManifestSha256: artifact.sha256,
        interactionManifestKnownGapCount: interactionManifest.knownGapCount,
        attestationCreatedAt: createdAt,
      });
      releaseEvidence = {
        status: "validated",
        path: validatedEvidence.path,
        sha256: validatedEvidence.sha256,
        releaseId: validatedEvidence.bundle.releaseId,
        validatedGateCount: validatedEvidence.bundle.gates.length,
      };
    } catch (error) {
      releaseEvidence = {
        status: "invalid",
        path: evidencePath,
        sha256: null,
        releaseId: null,
        validatedGateCount: 0,
      };
      blockers.push(`Release-gate evidence validation failed: ${error instanceof Error ? error.message : "unknown validation error"}`);
    }
  }

  let validatedSignOff: ValidatedReleaseSignOff | undefined;
  let humanSignOff: ReleaseSignOffReceipt = {
    status: "not-supplied",
    path: null,
    sha256: null,
    approvedBy: null,
    approvedAt: null,
    trustedPublicKeySha256: null,
  };
  if (!input.humanSignOffPath) {
    blockers.push("No cryptographically signed human release approval was supplied");
  } else if (!input.trustedSignOffPublicKeyPath) {
    humanSignOff = { ...humanSignOff, status: "invalid", path: resolve(input.humanSignOffPath) };
    blockers.push("A human release sign-off was supplied without a trusted Ed25519 public key");
  } else if (!validatedEvidence) {
    humanSignOff = { ...humanSignOff, status: "invalid", path: resolve(input.humanSignOffPath) };
    blockers.push("Human release sign-off cannot be verified until the release-gate evidence bundle is valid");
  } else {
    const signOffPath = resolve(input.humanSignOffPath);
    try {
      validatedSignOff = validateReleaseSignOff(
        signOffPath,
        resolve(input.trustedSignOffPublicKeyPath),
        validatedEvidence,
        {
          gitHead: git.head,
          sourceManifestSha256: source.sha256,
          artifactManifestSha256: artifact.sha256,
          attestationCreatedAt: createdAt,
        },
      );
      humanSignOff = {
        status: "verified",
        path: validatedSignOff.path,
        sha256: validatedSignOff.sha256,
        approvedBy: validatedSignOff.signOff.approvedBy,
        approvedAt: validatedSignOff.signOff.approvedAt,
        trustedPublicKeySha256: validatedSignOff.trustedPublicKeySha256,
      };
    } catch (error) {
      humanSignOff = { ...humanSignOff, status: "invalid", path: signOffPath };
      blockers.push(`Human release sign-off validation failed: ${error instanceof Error ? error.message : "unknown validation error"}`);
    }
  }

  const signed = validatedSignOff !== undefined;
  const releaseCandidateEligible = immutableSourceAttested
    && interactionManifest.status === "validated"
    && interactionManifest.knownGapCount === 0
    && validatedEvidence !== undefined
    && signed
    && blockers.length === 0;
  return {
    schemaVersion: "ti-scale.release-attestation.v1",
    createdAt,
    immutableSourceAttested,
    releaseCandidateEligible,
    signed,
    blockers,
    interactionManifest,
    releaseEvidence,
    humanSignOff,
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

function optionalPathArgument(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a path argument`);
  return resolve(process.cwd(), value);
}

async function main(): Promise<void> {
  const applicationRoot = resolve(import.meta.dir, "..");
  const repositoryRoot = await requiredCommand("/usr/bin/git", ["rev-parse", "--show-toplevel"], applicationRoot);
  const outputFlag = process.argv.indexOf("--output");
  const output = outputFlag >= 0 && process.argv[outputFlag + 1]
    ? resolve(process.cwd(), process.argv[outputFlag + 1]!)
    : resolve(applicationRoot, "test-results/attestations/ti-scale-release-attestation.json");
  const attestation = await buildReleaseAttestation({
    repositoryRoot,
    applicationRoot,
    artifactRoot: resolve(applicationRoot, "dist"),
    releaseEvidencePath: optionalPathArgument("--evidence"),
    humanSignOffPath: optionalPathArgument("--sign-off"),
    trustedSignOffPublicKeyPath: optionalPathArgument("--trusted-sign-off-key"),
  });
  writeAttestationAtomically(output, attestation);
  console.log(JSON.stringify({
    output,
    immutableSourceAttested: attestation.immutableSourceAttested,
    releaseCandidateEligible: attestation.releaseCandidateEligible,
    signed: attestation.signed,
    releaseEvidence: attestation.releaseEvidence,
    humanSignOff: attestation.humanSignOff,
    sourceManifest: attestation.source.sha256,
    artifactManifest: attestation.artifact.sha256,
    blockers: attestation.blockers,
  }, null, 2));
  if (!attestation.releaseCandidateEligible && !process.argv.includes("--allow-ineligible")) process.exitCode = 1;
}

if (import.meta.main) await main();
