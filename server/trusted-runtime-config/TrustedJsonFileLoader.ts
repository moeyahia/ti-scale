import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  type BigIntStats,
} from "node:fs";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import { digestCanonicalJson } from "../mcp/canonicalJson";

export const TRUSTED_LOCAL_FILE_RECEIPT_SCHEMA_VERSION =
  "ti-scale.trusted-local-file-receipt.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const DEFAULT_MAXIMUM_BYTES = 2 * 1_024 * 1_024;

export interface TrustedJsonFileReference {
  /** Absolute, operator-controlled JSON file path. */
  readonly path: string;
  /** Absolute directory that owns the permitted configuration namespace. */
  readonly trustRoot: string;
  /** SHA-256 of the exact reviewed file bytes, normally supplied by deployment. */
  readonly expectedSha256: string;
  /** Root-only by default. Tests or an isolated deployment may explicitly add its service UID. */
  readonly allowedOwnerUids?: readonly number[];
  readonly maximumBytes?: number;
}

export interface TrustedLocalFileReceipt {
  readonly schemaVersion: typeof TRUSTED_LOCAL_FILE_RECEIPT_SCHEMA_VERSION;
  readonly sourcePath: string;
  readonly trustRoot: string;
  readonly sourceSha256: string;
  readonly canonicalSha256: string;
  readonly byteSize: number;
  readonly ownerUid: number;
  readonly ownerGid: number;
  readonly mode: number;
  readonly device: string;
  readonly inode: string;
}

export interface LoadedTrustedJson<T> {
  readonly value: T;
  readonly receipt: TrustedLocalFileReceipt;
}

interface TrustedBytes {
  readonly bytes: Buffer;
  readonly sourcePath: string;
  readonly trustRoot: string;
  readonly sourceSha256: string;
  readonly ownerUid: number;
  readonly ownerGid: number;
  readonly mode: number;
  readonly device: string;
  readonly inode: string;
}

function absolutePath(value: string, label: string): string {
  if (!value || !isAbsolute(value) || value.length > 4_096 || CONTROL_CHARACTERS.test(value)) {
    throw new Error(`${label} must be an absolute path without control characters`);
  }
  return resolve(value);
}

function isInside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

function ownerUids(values: readonly number[] | undefined): ReadonlySet<number> {
  const configured = values ?? [0];
  if (configured.length < 1 || configured.length > 8) {
    throw new Error("Trusted file allowedOwnerUids must contain one to eight UIDs");
  }
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const normalized = configured.map((value) => {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Trusted file allowedOwnerUids contains an invalid UID");
    }
    if (value !== 0 && value !== currentUid) {
      throw new Error("Trusted files may be owned only by root or the current isolated service UID");
    }
    return value;
  });
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("Trusted file allowedOwnerUids contains duplicates");
  }
  return new Set(normalized);
}

function lstatBigInt(path: string): BigIntStats {
  const metadata = lstatSync(path, { bigint: true });
  if (!metadata) throw new Error("Trusted configuration path disappeared");
  return metadata;
}

function fstatBigInt(descriptor: number): BigIntStats {
  return fstatSync(descriptor, { bigint: true });
}

function assertTrustedMetadata(
  metadata: BigIntStats,
  allowedOwners: ReadonlySet<number>,
  label: string,
  kind: "directory" | "file",
): void {
  if (metadata.isSymbolicLink() || (kind === "directory" ? !metadata.isDirectory() : !metadata.isFile())) {
    throw new Error(`${label} must be a regular non-symlink ${kind}`);
  }
  const uid = Number(metadata.uid);
  const mode = Number(metadata.mode & 0o7777n);
  if (!allowedOwners.has(uid) || (mode & 0o022) !== 0) {
    throw new Error(`${label} must have a trusted owner and must not be group/world writable`);
  }
  if (kind === "file" && (mode & 0o7111) !== 0) {
    throw new Error(`${label} must be non-executable and must not have special permission bits`);
  }
}

function sameIdentity(
  left: BigIntStats,
  right: BigIntStats,
): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function assertTrustedPathChain(
  trustRoot: string,
  sourcePath: string,
  allowedOwners: ReadonlySet<number>,
): BigIntStats {
  const rootMetadata = lstatBigInt(trustRoot);
  assertTrustedMetadata(rootMetadata, allowedOwners, "Trusted configuration root", "directory");
  if (realpathSync(trustRoot) !== trustRoot) {
    throw new Error("Trusted configuration root must not resolve through a symlink");
  }

  const relativePath = relative(trustRoot, sourcePath);
  const segments = relativePath.split(sep).filter(Boolean);
  let current = trustRoot;
  for (const [index, segment] of segments.entries()) {
    current = resolve(current, segment);
    const metadata = lstatBigInt(current);
    const final = index === segments.length - 1;
    assertTrustedMetadata(
      metadata,
      allowedOwners,
      final ? "Trusted configuration file" : "Trusted configuration directory",
      final ? "file" : "directory",
    );
    if (final) return metadata;
  }
  throw new Error("Trusted configuration path must identify a file below its trust root");
}

function expectedDigest(value: string): Buffer {
  if (!SHA256.test(value)) {
    throw new Error("Trusted configuration expectedSha256 must be a lowercase SHA-256 digest");
  }
  return Buffer.from(value, "hex");
}

function maximumBytes(value: number | undefined): number {
  const limit = value ?? DEFAULT_MAXIMUM_BYTES;
  if (!Number.isSafeInteger(limit) || limit < 2 || limit > 8 * 1_024 * 1_024) {
    throw new Error("Trusted configuration maximumBytes must be between 2 and 8388608");
  }
  return limit;
}

function readTrustedBytes(reference: TrustedJsonFileReference): TrustedBytes {
  const trustRoot = absolutePath(reference.trustRoot, "Trusted configuration root");
  const sourcePath = absolutePath(reference.path, "Trusted configuration path");
  if (trustRoot === resolve(sep)) {
    throw new Error("Trusted configuration root must be narrower than the filesystem root");
  }
  if (!isInside(trustRoot, sourcePath) || sourcePath === trustRoot) {
    throw new Error("Trusted configuration path must remain below its trust root");
  }
  const allowedOwners = ownerUids(reference.allowedOwnerUids);
  const pathMetadata = assertTrustedPathChain(trustRoot, sourcePath, allowedOwners);
  const size = Number(pathMetadata.size);
  const limit = maximumBytes(reference.maximumBytes);
  if (!Number.isSafeInteger(size) || size < 2 || size > limit) {
    throw new Error(`Trusted configuration file must be between 2 and ${limit} bytes`);
  }

  let descriptor: number | undefined;
  try {
    descriptor = openSync(sourcePath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = fstatBigInt(descriptor);
    assertTrustedMetadata(opened, allowedOwners, "Opened trusted configuration", "file");
    if (!sameIdentity(pathMetadata, opened)) {
      throw new Error("Trusted configuration identity changed before it was read");
    }
    const bytes = readFileSync(descriptor);
    const after = fstatBigInt(descriptor);
    if (!sameIdentity(opened, after) || bytes.length !== Number(after.size)) {
      throw new Error("Trusted configuration identity changed while it was read");
    }
    const sourceSha256 = createHash("sha256").update(bytes).digest("hex");
    if (!timingSafeEqual(Buffer.from(sourceSha256, "hex"), expectedDigest(reference.expectedSha256))) {
      throw new Error("Trusted configuration file does not match its reviewed SHA-256");
    }
    return {
      bytes,
      sourcePath,
      trustRoot,
      sourceSha256,
      ownerUid: Number(after.uid),
      ownerGid: Number(after.gid),
      mode: Number(after.mode & 0o7777n),
      device: after.dev.toString(),
      inode: after.ino.toString(),
    };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

/**
 * Reads one deployment-pinned JSON document without following symlinks or
 * accepting a writable/unstable path. Parsing never executes code, expands
 * variables, interpolates a shell, or issues a database query.
 */
export function loadTrustedJson<T>(
  reference: TrustedJsonFileReference,
  parse: (input: unknown) => T,
): LoadedTrustedJson<T> {
  const trusted = readTrustedBytes(reference);
  const source = trusted.bytes.toString("utf8");
  if (!Buffer.from(source, "utf8").equals(trusted.bytes)) {
    throw new Error("Trusted configuration file must contain valid UTF-8");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(source) as unknown;
  } catch {
    throw new Error("Trusted configuration file must contain valid JSON");
  }
  const value = parse(raw);
  const canonical = digestCanonicalJson(value, {
    maxBytes: maximumBytes(reference.maximumBytes),
    maxDepth: 24,
  });
  return Object.freeze({
    value,
    receipt: Object.freeze({
      schemaVersion: TRUSTED_LOCAL_FILE_RECEIPT_SCHEMA_VERSION,
      sourcePath: trusted.sourcePath,
      trustRoot: trusted.trustRoot,
      sourceSha256: trusted.sourceSha256,
      canonicalSha256: canonical.sha256,
      byteSize: trusted.bytes.length,
      ownerUid: trusted.ownerUid,
      ownerGid: trusted.ownerGid,
      mode: trusted.mode,
      device: trusted.device,
      inode: trusted.inode,
    }),
  });
}
