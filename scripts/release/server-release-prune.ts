#!/usr/bin/env bun
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { canonicalJson } from "../../server/intelligence-v24/validation";
import type { JsonValue } from "../../server/intelligence-v24/types";
import { sha256File, verifyServerRelease } from "./FunctionalReleasePrimitives";
import { withSharedReleaseLock } from "./ReleaseExecutionBoundary";

export const SERVER_RELEASE_PRUNE_PLAN_ID = "obsolete-server-releases-20260721-v2";

export const SERVER_RELEASE_PRUNE_TARGETS = Object.freeze([
  "functional-live-clock-20260720T041610Z",
  "functional-recovery-20260720T085438Z",
  "functional-safe-recon-20260720T0817Z",
  "functional-tool-truth-20260720T091343Z",
  "owner-fence-tool-packs-20260720T092927Z",
  "readiness-web-tools-20260720T095944Z",
  "brain-anatomy-20260720T174050Z",
  "brain-bilateral-20260720T194913Z",
  "brain-atlas-webgl-20260720T2233Z",
  "brain-atlas-webgl-r2-20260720T2242Z",
] as const);

export const SERVER_RELEASE_PRUNE_PROTECTED = Object.freeze([
  "brain-full-import-20260721T160000Z",
  "brain-outcomes-visual-20260721T091557Z",
  "brain-dark-titanium-20260721T073740Z",
  "brain-atlas-anatomy-20260720T231117Z",
  "previous-functional-20260719T171300Z",
] as const);

const ACTIVE_RELEASE_ID = SERVER_RELEASE_PRUNE_PROTECTED[0];
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SAFE_ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$/u;

interface DeploymentReceipt {
  readonly schemaVersion: string;
  readonly releaseId: string;
  readonly status: string;
  readonly serverRelease?: {
    readonly path?: string;
    readonly manifestSha256?: string;
    readonly treeSha256?: string;
  };
  readonly backup?: {
    readonly root?: string;
    readonly metadata?: string;
    readonly checksumManifestSha256?: string;
  };
}

interface BackupMetadata {
  readonly schemaVersion?: string;
  readonly releaseId?: string;
  readonly serverRelease?: {
    readonly path?: string;
    readonly manifestSha256?: string;
  };
}

export interface ServerReleasePrunePreview {
  readonly schemaVersion: "ti-scale.server-release-prune-preview.v1";
  readonly planId: typeof SERVER_RELEASE_PRUNE_PLAN_ID;
  readonly releaseRoot: string;
  readonly backupRoot: string;
  readonly activeApplicationTarget: string;
  readonly currentPointerTarget: string | null;
  readonly protectedReleaseIds: readonly string[];
  readonly targets: readonly {
    readonly releaseId: string;
    readonly releasePath: string;
    readonly deploymentReceiptPath: string;
    readonly deploymentReceiptSha256: string;
    readonly backupChecksumManifestSha256: string;
    readonly backupMetadataSha256: string;
    readonly serverManifestSha256: string;
    readonly serverTreeSha256: string;
    readonly apparentBytes: number;
    readonly allocatedBytes: number;
  }[];
  readonly targetCount: number;
  readonly totalApparentBytes: number;
  readonly totalAllocatedBytes: number;
  readonly minimumReclaimableBytes: number;
  readonly backupPolicy: "read_only_preserved";
  readonly previewHash: string;
}

export interface ServerReleasePruneResult {
  readonly status: "completed";
  readonly planId: typeof SERVER_RELEASE_PRUNE_PLAN_ID;
  readonly previewHash: string;
  readonly deletedReleaseIds: readonly string[];
  readonly minimumReclaimableBytes: number;
  readonly receiptPath: string;
}

interface VerifiedRelease {
  readonly manifestSha256: string;
  readonly manifest: {
    readonly treeSha256: string;
    readonly totalBytes: number;
  };
}

export interface ServerReleasePruneOptions {
  readonly serverReleaseRoot?: string;
  readonly backupRoot?: string;
  readonly applicationPath?: string;
  readonly currentPointerPath?: string;
  readonly pruneReceiptRoot?: string;
  readonly clock?: () => Date;
  readonly uid?: () => number;
  readonly verifyRelease?: (
    releasePath: string,
    releaseId: string,
    expectedManifestSha256: string,
  ) => Promise<VerifiedRelease>;
}

interface AllocationEntry {
  readonly blocks: number;
  readonly links: number;
  occurrences: number;
}

interface PruneReceiptEvent {
  readonly sequence: number;
  readonly action: string;
  readonly occurredAt: string;
  readonly previousHash: string | null;
  readonly recordHash: string;
  readonly actorId?: string;
  readonly reason?: string;
  readonly previewHash?: string;
  readonly releaseId?: string;
  readonly error?: string;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeId(value: string, label: string): string {
  const normalized = value.trim();
  if (!SAFE_ID.test(normalized) || normalized === "." || normalized === "..") {
    throw new Error(`${label} is not a safe release identifier`);
  }
  return normalized;
}

function boundedText(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 1_000 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new Error(`${label} must contain 1 to 1000 printable characters`);
  }
  return normalized;
}

function actorId(value: string): string {
  const normalized = value.trim();
  if (!SAFE_ACTOR.test(normalized)) throw new Error("Actor ID is not a safe identifier");
  return normalized;
}

function exactChild(rootValue: string, childValue: string, label: string): string {
  const root = resolve(rootValue);
  const child = resolve(childValue);
  const suffix = relative(root, child);
  if (!suffix || suffix === ".." || suffix.startsWith(`..${sep}`) || suffix.startsWith(sep)) {
    throw new Error(`${label} is not an exact child of its protected root`);
  }
  return child;
}

function realDirectory(pathValue: string, label: string): string {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error(`${label} must be a real, non-link directory`);
  }
  return path;
}

function boundedJsonFile(pathValue: string, label: string): unknown {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 2 * 1024 * 1024) {
    throw new Error(`${label} must be a regular, non-link JSON file no larger than 2 MiB`);
  }
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}

function checksumEntries(value: string): ReadonlyMap<string, string> {
  const entries = new Map<string, string>();
  for (const line of value.trim().split("\n")) {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9._/-]+)$/u.exec(line);
    if (!match || entries.has(match[2]!)) throw new Error("Backup checksum manifest is malformed");
    entries.set(match[2]!, match[1]!);
  }
  if (entries.size === 0) throw new Error("Backup checksum manifest is empty");
  return entries;
}

function walkAllocation(
  path: string,
  allocation: Map<string, AllocationEntry>,
): number {
  const metadata = lstatSync(path);
  const key = `${metadata.dev}:${metadata.ino}`;
  const current = allocation.get(key);
  if (current) current.occurrences += 1;
  else allocation.set(key, {
    blocks: metadata.blocks * 512,
    links: metadata.nlink,
    occurrences: 1,
  });
  let bytes = metadata.blocks * 512;
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    for (const entry of readdirSync(path)) bytes += walkAllocation(join(path, entry), allocation);
  }
  return bytes;
}

function writeJsonAtomically(pathValue: string, value: unknown): void {
  const path = resolve(pathValue);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  renameSync(temporary, path);
}

function eventHash(previousHash: string | null, value: unknown): string {
  return sha256(`${previousHash ?? ""}\n${canonicalJson(value as JsonValue)}`);
}

export class ServerReleasePruneService {
  readonly #serverReleaseRoot: string;
  readonly #backupRoot: string;
  readonly #applicationPath: string;
  readonly #currentPointerPath: string;
  readonly #pruneReceiptRoot: string;
  readonly #clock: () => Date;
  readonly #uid: () => number;
  readonly #verifyRelease: NonNullable<ServerReleasePruneOptions["verifyRelease"]>;

  constructor(options: ServerReleasePruneOptions = {}) {
    void options;
    throw new Error(
      "Backup-coupled server release pruning is disabled by operator no-backup policy",
    );
    /* c8 ignore start -- unreachable retired backup-coupled pruning implementation */
    this.#serverReleaseRoot = resolve(options.serverReleaseRoot ?? "/opt/ti-scale-server-releases/releases");
    this.#backupRoot = resolve(options.backupRoot ?? "/var/backups/ti-scale/releases");
    this.#applicationPath = resolve(options.applicationPath ?? "/opt/ti-scale");
    this.#currentPointerPath = resolve(options.currentPointerPath ?? "/opt/ti-scale-server-releases/current");
    this.#pruneReceiptRoot = resolve(options.pruneReceiptRoot ?? "/var/backups/ti-scale/release-prunes");
    this.#clock = options.clock ?? (() => new Date());
    this.#uid = options.uid ?? (() => process.getuid?.() ?? -1);
    this.#verifyRelease = options.verifyRelease ?? verifyServerRelease;
    /* c8 ignore stop */
  }

  async preview(): Promise<ServerReleasePrunePreview> {
    const releaseRoot = realDirectory(this.#serverReleaseRoot, "Server release root");
    const backupRoot = realDirectory(this.#backupRoot, "Release backup root");
    const targets = SERVER_RELEASE_PRUNE_TARGETS.map((value) => safeId(value, "Prune target"));
    const protectedReleaseIds = SERVER_RELEASE_PRUNE_PROTECTED.map((value) => safeId(value, "Protected release"));
    if (new Set(targets).size !== targets.length || new Set(protectedReleaseIds).size !== protectedReleaseIds.length) {
      throw new Error("Release prune plan contains duplicate identifiers");
    }
    if (targets.some((target) => protectedReleaseIds.includes(target as typeof SERVER_RELEASE_PRUNE_PROTECTED[number]))) {
      throw new Error("Release prune target overlaps the protected release set");
    }

    for (const releaseId of protectedReleaseIds) {
      realDirectory(exactChild(releaseRoot, join(releaseRoot, releaseId), `Protected release ${releaseId}`), `Protected release ${releaseId}`);
    }
    const applicationMetadata = lstatSync(this.#applicationPath);
    if (!applicationMetadata.isSymbolicLink()) throw new Error("Active application pointer must remain a symbolic link");
    const activeApplicationTarget = realpathSync(this.#applicationPath);
    const expectedActiveTarget = join(releaseRoot, ACTIVE_RELEASE_ID);
    if (activeApplicationTarget !== expectedActiveTarget) {
      throw new Error("Active application pointer does not match the protected active release");
    }
    const currentPointerTarget = existsSync(this.#currentPointerPath)
      ? (() => {
          if (!lstatSync(this.#currentPointerPath).isSymbolicLink()) {
            throw new Error("Server-release current pointer is not a symbolic link");
          }
          const target = realpathSync(this.#currentPointerPath);
          if (!protectedReleaseIds.some((releaseId) => target === join(releaseRoot, releaseId))) {
            throw new Error("Server-release current pointer does not resolve to a protected release");
          }
          return target;
        })()
      : null;

    const allocation = new Map<string, AllocationEntry>();
    const verifiedTargets: Omit<ServerReleasePrunePreview, "previewHash">["targets"][number][] = [];
    for (const releaseId of targets) {
      const releasePath = realDirectory(
        exactChild(releaseRoot, join(releaseRoot, releaseId), `Release ${releaseId}`),
        `Release ${releaseId}`,
      );
      if (releasePath === activeApplicationTarget || currentPointerTarget === releasePath) {
        throw new Error(`Refusing to prune active release ${releaseId}`);
      }
      const backupDirectory = realDirectory(
        exactChild(backupRoot, join(backupRoot, releaseId), `Backup ${releaseId}`),
        `Backup ${releaseId}`,
      );
      const deploymentReceiptPath = join(backupDirectory, "deployment-receipt.json");
      const receipt = boundedJsonFile(deploymentReceiptPath, `Deployment receipt ${releaseId}`) as DeploymentReceipt;
      const expectedReleasePath = join(releaseRoot, releaseId);
      if (
        receipt.schemaVersion !== "ti-scale.functional-release-receipt.v1" ||
        receipt.releaseId !== releaseId || receipt.status !== "deployed" ||
        resolve(receipt.serverRelease?.path ?? "") !== expectedReleasePath ||
        !SHA256.test(receipt.serverRelease?.manifestSha256 ?? "") ||
        !SHA256.test(receipt.serverRelease?.treeSha256 ?? "") ||
        resolve(receipt.backup?.root ?? "") !== backupDirectory ||
        resolve(receipt.backup?.metadata ?? "") !== join(backupDirectory, "backup-metadata.json") ||
        !SHA256.test(receipt.backup?.checksumManifestSha256 ?? "")
      ) throw new Error(`Deployment receipt does not prove release ${releaseId}`);

      const checksumManifestPath = join(backupDirectory, "SHA256SUMS");
      const checksumManifestBytes = readFileSync(checksumManifestPath);
      const backupChecksumManifestSha256 = sha256(checksumManifestBytes);
      if (backupChecksumManifestSha256 !== receipt.backup!.checksumManifestSha256) {
        throw new Error(`Backup checksum receipt mismatch for ${releaseId}`);
      }
      const checksums = checksumEntries(checksumManifestBytes.toString("utf8"));
      const backupMetadataPath = join(backupDirectory, "backup-metadata.json");
      const backupMetadataSha256 = await sha256File(backupMetadataPath);
      if (checksums.get("backup-metadata.json") !== backupMetadataSha256) {
        throw new Error(`Checksum-bound backup metadata mismatch for ${releaseId}`);
      }
      const backupMetadata = boundedJsonFile(backupMetadataPath, `Backup metadata ${releaseId}`) as BackupMetadata;
      if (
        backupMetadata.schemaVersion !== "ti-scale.functional-release-backup.v1" ||
        backupMetadata.releaseId !== releaseId ||
        resolve(backupMetadata.serverRelease?.path ?? "") !== expectedReleasePath ||
        backupMetadata.serverRelease?.manifestSha256 !== receipt.serverRelease!.manifestSha256
      ) throw new Error(`Backup metadata does not bind release ${releaseId}`);

      const verified = await this.#verifyRelease(
        releasePath,
        releaseId,
        receipt.serverRelease!.manifestSha256!,
      );
      if (
        verified.manifestSha256 !== receipt.serverRelease!.manifestSha256 ||
        verified.manifest.treeSha256 !== receipt.serverRelease!.treeSha256
      ) throw new Error(`Immutable server tree differs from the deployment receipt for ${releaseId}`);
      const allocatedBytes = walkAllocation(releasePath, allocation);
      verifiedTargets.push(Object.freeze({
        releaseId,
        releasePath,
        deploymentReceiptPath,
        deploymentReceiptSha256: await sha256File(deploymentReceiptPath),
        backupChecksumManifestSha256,
        backupMetadataSha256,
        serverManifestSha256: verified.manifestSha256,
        serverTreeSha256: verified.manifest.treeSha256,
        apparentBytes: verified.manifest.totalBytes,
        allocatedBytes,
      }));
    }

    const minimumReclaimableBytes = [...allocation.values()]
      .filter((entry) => entry.occurrences >= entry.links)
      .reduce((sum, entry) => sum + entry.blocks, 0);
    const unsigned = {
      schemaVersion: "ti-scale.server-release-prune-preview.v1" as const,
      planId: SERVER_RELEASE_PRUNE_PLAN_ID,
      releaseRoot,
      backupRoot,
      activeApplicationTarget,
      currentPointerTarget,
      protectedReleaseIds: Object.freeze([...protectedReleaseIds]),
      targets: Object.freeze(verifiedTargets),
      targetCount: verifiedTargets.length,
      totalApparentBytes: verifiedTargets.reduce((sum, target) => sum + target.apparentBytes, 0),
      totalAllocatedBytes: verifiedTargets.reduce((sum, target) => sum + target.allocatedBytes, 0),
      minimumReclaimableBytes,
      backupPolicy: "read_only_preserved" as const,
    } as const;
    return Object.freeze({ ...unsigned, previewHash: sha256(canonicalJson(unsigned)) });
  }

  async execute(input: {
    readonly expectedPreviewHash: string;
    readonly confirmation: string;
    readonly actorId: string;
    readonly reason: string;
  }): Promise<ServerReleasePruneResult> {
    if (this.#uid() !== 0) throw new Error("Server release pruning requires root");
    if (input.confirmation !== SERVER_RELEASE_PRUNE_PLAN_ID) {
      throw new Error(`Confirmation must exactly match ${SERVER_RELEASE_PRUNE_PLAN_ID}`);
    }
    if (!SHA256.test(input.expectedPreviewHash)) throw new Error("Expected preview hash must be a lowercase SHA-256");
    const resolvedActorId = actorId(input.actorId);
    const reason = boundedText(input.reason, "Prune reason");
    const preview = await this.preview();
    if (preview.previewHash !== input.expectedPreviewHash) {
      throw new Error("Release prune preview changed; review a fresh preview before execution");
    }

    const receiptPath = join(this.#pruneReceiptRoot, `${SERVER_RELEASE_PRUNE_PLAN_ID}.json`);
    if (existsSync(receiptPath)) throw new Error("Release prune receipt already exists; automatic repeat execution is refused");
    const quarantineRoot = join(dirname(this.#serverReleaseRoot), "prune-quarantine", SERVER_RELEASE_PRUNE_PLAN_ID);
    if (existsSync(quarantineRoot)) throw new Error("Release prune quarantine already exists; manual reconciliation is required");
    mkdirSync(quarantineRoot, { recursive: true, mode: 0o700 });
    const occurredAt = this.#clock().toISOString();
    const initialEvent = {
      sequence: 1,
      action: "prune_started",
      actorId: resolvedActorId,
      reason,
      occurredAt,
      previewHash: preview.previewHash,
    } as const;
    const initialHash = eventHash(null, initialEvent);
    const events: PruneReceiptEvent[] = [{
      ...initialEvent,
      previousHash: null,
      recordHash: initialHash,
    }];
    const receipt = {
      schemaVersion: "ti-scale.server-release-prune-receipt.v1",
      planId: SERVER_RELEASE_PRUNE_PLAN_ID,
      status: "executing" as "executing" | "completed" | "failed",
      preview,
      actorId: resolvedActorId,
      reason,
      backupPolicy: "read_only_preserved",
      events,
      deletedReleaseIds: [] as string[],
    };
    writeJsonAtomically(receiptPath, receipt);

    try {
      for (const target of preview.targets) {
        const quarantinePath = join(quarantineRoot, target.releaseId);
        renameSync(target.releasePath, quarantinePath);
        rmSync(quarantinePath, { recursive: true, force: false });
        receipt.deletedReleaseIds.push(target.releaseId);
        const previousHash = receipt.events.at(-1)!.recordHash;
        const event = {
          sequence: receipt.events.length + 1,
          action: "release_deleted",
          releaseId: target.releaseId,
          occurredAt: this.#clock().toISOString(),
        } as const;
        receipt.events.push({ ...event, previousHash, recordHash: eventHash(previousHash, event) });
        writeJsonAtomically(receiptPath, receipt);
      }
      rmSync(quarantineRoot, { recursive: true, force: false });
      receipt.status = "completed";
      const previousHash = receipt.events.at(-1)!.recordHash;
      const event = {
        sequence: receipt.events.length + 1,
        action: "prune_completed",
        occurredAt: this.#clock().toISOString(),
      } as const;
      receipt.events.push({ ...event, previousHash, recordHash: eventHash(previousHash, event) });
      writeJsonAtomically(receiptPath, receipt);
      return Object.freeze({
        status: "completed" as const,
        planId: SERVER_RELEASE_PRUNE_PLAN_ID,
        previewHash: preview.previewHash,
        deletedReleaseIds: Object.freeze([...receipt.deletedReleaseIds]),
        minimumReclaimableBytes: preview.minimumReclaimableBytes,
        receiptPath,
      });
    } catch (error) {
      receipt.status = "failed";
      const previousHash = receipt.events.at(-1)!.recordHash;
      const event = {
        sequence: receipt.events.length + 1,
        action: "prune_failed",
        occurredAt: this.#clock().toISOString(),
        error: error instanceof Error ? error.message.slice(0, 1_000) : "unknown error",
      } as const;
      receipt.events.push({ ...event, previousHash, recordHash: eventHash(previousHash, event) });
      writeJsonAtomically(receiptPath, receipt);
      throw error;
    }
  }
}

interface CliArguments {
  readonly command: "preview" | "execute";
  readonly values: ReadonlyMap<string, string>;
}

export function parseServerReleasePruneArguments(argv: readonly string[]): CliArguments {
  const [command, ...rest] = argv;
  if (command !== "preview" && command !== "execute") throw new Error("Command must be preview or execute");
  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`${token} requires a value`);
    if (values.has(token)) throw new Error(`Duplicate option: ${token}`);
    values.set(token, next);
    index += 1;
  }
  const allowed = command === "preview"
    ? new Set<string>()
    : new Set(["--expected-preview-hash", "--confirm", "--actor", "--reason"]);
  for (const key of values.keys()) if (!allowed.has(key)) throw new Error(`Unsupported ${command} option: ${key}`);
  if (command === "execute") {
    for (const key of allowed) if (!values.get(key)?.trim()) throw new Error(`${key} is required`);
  }
  return { command, values };
}

async function main(argv = process.argv.slice(2)): Promise<number> {
  const args = parseServerReleasePruneArguments(argv);
  const service = new ServerReleasePruneService();
  const result = args.command === "preview"
    ? await service.preview()
    : await withSharedReleaseLock(
        () => service.execute({
          expectedPreviewHash: args.values.get("--expected-preview-hash")!,
          confirmation: args.values.get("--confirm")!,
          actorId: args.values.get("--actor")!,
          reason: args.values.get("--reason")!,
        }),
        { operation: "server-release-prune" },
      );
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return 0;
}

if (import.meta.main) {
  process.stderr.write(
    "Backup-coupled server release pruning is disabled by the operator no-backup policy\n",
  );
  process.exitCode = 1;
}
