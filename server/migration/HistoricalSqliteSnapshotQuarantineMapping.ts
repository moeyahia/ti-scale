import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { checkDatabaseIntegrity, createDatabaseConnection } from "../db/connection";
import { canonicalJson, hashJson } from "../orchestration/serialization";
import {
  loadTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import {
  HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION,
  HISTORICAL_SQLITE_SOURCE_ATTESTATION_SCHEMA_VERSION,
  inspectHistoricalSqliteSource,
  type HistoricalSqliteFileIdentity,
  type HistoricalSqlitePresentFileIdentity,
  type HistoricalSqliteSnapshotReceipt,
} from "./HistoricalSqliteSnapshotService";

export const HISTORICAL_SQLITE_SNAPSHOT_QUARANTINE_MAPPING_SCHEMA_VERSION =
  "ti_scale.historical_sqlite_snapshot_quarantine_mapping/v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const O_NOATIME = process.platform === "linux" ? 0o1000000 : 0;

type SourceRole = HistoricalSqlitePresentFileIdentity["role"];
type JsonRecord = Record<string, unknown>;

export interface ReceiptBoundSqliteQuarantineFile {
  readonly role: SourceRole;
  readonly path: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sourceDevice: number;
  readonly sourceInode: number;
  readonly sourceModifiedTimeNanoseconds: string;
  readonly snapshotReceiptSha256: string;
  readonly normalizedSnapshotSha256: string;
  readonly mappingId: string;
}

export interface HistoricalSqliteSnapshotQuarantineMapping {
  readonly schemaVersion:
    typeof HISTORICAL_SQLITE_SNAPSHOT_QUARANTINE_MAPPING_SCHEMA_VERSION;
  readonly mappingId: string;
  readonly disposition: "quarantined_no_semantic_records";
  readonly reasonCode: "empty_sqlmap_storage_snapshot";
  readonly snapshotId: string;
  readonly snapshotReceiptSha256: string;
  readonly snapshotReceiptPayloadSha256: string;
  readonly sourceBundleSha256: string;
  readonly normalizedSnapshotSha256: string;
  readonly normalizedSnapshotBytes: number;
  readonly normalizedSchemaFingerprint: string;
  readonly semanticRowCount: 0;
  readonly sourceFiles: readonly ReceiptBoundSqliteQuarantineFile[];
}

function record(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonRecord;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value || value !== value.trim()) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  const result = text(value, label);
  if (!SHA256.test(result)) throw new Error(`${label} must be a lowercase SHA-256`);
  return result;
}

function absolutePath(value: unknown, label: string): string {
  const path = text(value, label);
  if (!isAbsolute(path) || resolve(path) !== path || /[\u0000-\u001f\u007f]/u.test(path)) {
    throw new Error(`${label} must be a normalized absolute path`);
  }
  return path;
}

function safeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error(`${label} is invalid`);
  return Number(value);
}

function identityNumber(value: string, label: string): number {
  if (!/^\d+$/u.test(value)) throw new Error(`${label} is invalid`);
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0) throw new Error(`${label} exceeds the supported identity range`);
  return result;
}

function parsePresentFile(value: unknown, role: SourceRole): HistoricalSqlitePresentFileIdentity {
  const input = record(value, `${role} source identity`);
  if (input.present !== true || input.role !== role) {
    throw new Error(`${role} source identity is not a present ${role} file`);
  }
  return {
    role,
    path: absolutePath(input.path, `${role}.path`),
    present: true,
    device: text(input.device, `${role}.device`),
    inode: text(input.inode, `${role}.inode`),
    sizeBytes: safeInteger(input.sizeBytes, `${role}.sizeBytes`),
    modifiedAt: text(input.modifiedAt, `${role}.modifiedAt`),
    accessTimeNanoseconds: text(input.accessTimeNanoseconds, `${role}.accessTimeNanoseconds`),
    modifiedTimeNanoseconds: text(input.modifiedTimeNanoseconds, `${role}.modifiedTimeNanoseconds`),
    changeTimeNanoseconds: text(input.changeTimeNanoseconds, `${role}.changeTimeNanoseconds`),
    sha256: digest(input.sha256, `${role}.sha256`),
  };
}

function parseSourceFiles(value: unknown): Record<SourceRole, HistoricalSqliteFileIdentity> {
  const input = record(value, "source files");
  const database = parsePresentFile(input.database, "database");
  const parseSidecar = (role: "wal" | "shm"): HistoricalSqliteFileIdentity => {
    const candidate = record(input[role], `${role} source identity`);
    if (candidate.present === false && candidate.role === role) {
      return {
        role,
        path: absolutePath(candidate.path, `${role}.path`),
        present: false,
      };
    }
    return parsePresentFile(candidate, role);
  };
  return { database, wal: parseSidecar("wal"), shm: parseSidecar("shm") };
}

function parseSourceAttestation(value: unknown): HistoricalSqliteSnapshotReceipt["sourceBefore"] {
  const input = record(value, "source attestation");
  if (input.schemaVersion !== HISTORICAL_SQLITE_SOURCE_ATTESTATION_SCHEMA_VERSION) {
    throw new Error("Historical SQLite source attestation schema is unsupported");
  }
  const files = parseSourceFiles(input.files);
  const databasePath = absolutePath(input.canonicalDatabasePath, "canonicalDatabasePath");
  if (files.database.path !== databasePath
    || files.wal.path !== `${databasePath}-wal`
    || files.shm.path !== `${databasePath}-shm`) {
    throw new Error("Historical SQLite receipt source paths do not form one DB/WAL/SHM bundle");
  }
  const openHandleCheck = record(input.openHandleCheck, "openHandleCheck");
  if (!Array.isArray(openHandleCheck.matchingHandles) || openHandleCheck.matchingHandles.length !== 0) {
    throw new Error("Historical SQLite receipt was not captured from a closed source bundle");
  }
  return {
    schemaVersion: HISTORICAL_SQLITE_SOURCE_ATTESTATION_SCHEMA_VERSION,
    checkedAt: text(input.checkedAt, "source checkedAt"),
    containmentRoot: absolutePath(input.containmentRoot, "source containmentRoot"),
    requestedDatabasePath: absolutePath(input.requestedDatabasePath, "requestedDatabasePath"),
    canonicalDatabasePath: databasePath,
    files,
    committedWalPresent: input.committedWalPresent === true,
    sourceBundleSha256: digest(input.sourceBundleSha256, "sourceBundleSha256"),
    openHandleCheck: {
      checkedAt: text(openHandleCheck.checkedAt, "openHandleCheck.checkedAt"),
      platform: openHandleCheck.platform === "linux-procfs"
        ? "linux-procfs"
        : (() => { throw new Error("Historical SQLite receipt has an unsupported handle-check platform"); })(),
      inspectedProcesses: safeInteger(openHandleCheck.inspectedProcesses, "openHandleCheck.inspectedProcesses"),
      inspectedDescriptors: safeInteger(openHandleCheck.inspectedDescriptors, "openHandleCheck.inspectedDescriptors"),
      matchingHandles: [],
    },
  };
}

/** Parse and seal-check the existing snapshot receipt without trusting a cast. */
export function parseHistoricalSqliteSnapshotReceiptForQuarantine(
  value: unknown,
): HistoricalSqliteSnapshotReceipt {
  const input = record(value, "Historical SQLite snapshot receipt");
  if (input.schemaVersion !== HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION) {
    throw new Error("Historical SQLite snapshot receipt schema is unsupported");
  }
  if (input.method !== "attested_byte_clone_then_readonly_sqlite_online_backup"
    || input.sourceUnchanged !== true) {
    throw new Error("Historical SQLite snapshot receipt lacks its immutable source contract");
  }
  const receiptPayloadSha256 = digest(input.receiptPayloadSha256, "receiptPayloadSha256");
  const { receiptPayloadSha256: _seal, ...unsealed } = input;
  if (hashJson(unsealed) !== receiptPayloadSha256) {
    throw new Error("Historical SQLite snapshot receipt seal does not verify");
  }
  const sourceBefore = parseSourceAttestation(input.sourceBefore);
  const sourceAfter = parseSourceAttestation(input.sourceAfter);
  if (sourceBefore.sourceBundleSha256 !== sourceAfter.sourceBundleSha256
    || canonicalJson(sourceBefore.files) !== canonicalJson(sourceAfter.files)) {
    throw new Error("Historical SQLite snapshot receipt source identities do not match");
  }
  const normalized = record(input.normalizedSnapshot, "normalizedSnapshot");
  if (normalized.mode !== "0600" || normalized.journalMode !== "delete"
    || normalized.foreignKeyViolations !== 0
    || canonicalJson(normalized.quickCheck) !== canonicalJson(["ok"])
    || canonicalJson(normalized.integrityCheck) !== canonicalJson(["ok"])
    || !Array.isArray(normalized.nonEmptySidecars)
    || normalized.nonEmptySidecars.length !== 0) {
    throw new Error("Historical SQLite normalized snapshot receipt is not a clean standalone database");
  }
  return {
    schemaVersion: HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION,
    snapshotId: text(input.snapshotId, "snapshotId"),
    createdAt: text(input.createdAt, "createdAt"),
    method: "attested_byte_clone_then_readonly_sqlite_online_backup",
    sourceBefore,
    sourceAfter,
    sourceUnchanged: true,
    normalizedSnapshot: {
      path: absolutePath(normalized.path, "normalizedSnapshot.path"),
      sha256: digest(normalized.sha256, "normalizedSnapshot.sha256"),
      sizeBytes: safeInteger(normalized.sizeBytes, "normalizedSnapshot.sizeBytes"),
      mode: "0600",
      sqliteOnlineBackupPages: safeInteger(
        normalized.sqliteOnlineBackupPages,
        "normalizedSnapshot.sqliteOnlineBackupPages",
      ),
      quickCheck: ["ok"],
      integrityCheck: ["ok"],
      foreignKeyViolations: 0,
      journalMode: "delete",
      nonEmptySidecars: [],
    },
    receiptPath: absolutePath(input.receiptPath, "receiptPath"),
    receiptPayloadSha256,
  };
}

interface StableFileFingerprint {
  readonly sha256: string;
  readonly byteSize: number;
  readonly device: string;
  readonly inode: string;
  readonly modifiedTimeNanoseconds: string;
}

function stableFileFingerprint(path: string): StableFileFingerprint {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error("Receipt-bound SQLite source must remain a regular non-symlink file");
  }
  let descriptor: number | undefined;
  try {
    try {
      descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | O_NOATIME);
    } catch (error) {
      if (O_NOATIME === 0 || (error as NodeJS.ErrnoException).code !== "EPERM") throw error;
      throw new Error("Receipt-bound SQLite verification requires O_NOATIME permission");
    }
    const opened = fstatSync(descriptor, { bigint: true });
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size
      || opened.mtimeNs !== before.mtimeNs || opened.ctimeNs !== before.ctimeNs) {
      throw new Error("Receipt-bound SQLite source changed before verification");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (true) {
      const length = readSync(descriptor, buffer, 0, buffer.length, position);
      if (!length) break;
      hash.update(buffer.subarray(0, length));
      position += length;
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size
      || after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs) {
      throw new Error("Receipt-bound SQLite source changed during verification");
    }
    return {
      sha256: hash.digest("hex"),
      byteSize: Number(after.size),
      device: after.dev.toString(),
      inode: after.ino.toString(),
      modifiedTimeNanoseconds: after.mtimeNs.toString(),
    };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function isInside(root: string, candidate: string): boolean {
  const value = relative(resolve(root), resolve(candidate));
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

function validateEmptySqlmapSnapshot(path: string, expectedSha256: string, expectedBytes: number): string {
  for (const suffix of ["-wal", "-journal", "-shm"] as const) {
    if (existsSync(`${path}${suffix}`) && lstatSync(`${path}${suffix}`).size > 0) {
      throw new Error("Historical normalized SQLite snapshot acquired a non-empty sidecar");
    }
  }
  const before = stableFileFingerprint(path);
  if (before.sha256 !== expectedSha256 || before.byteSize !== expectedBytes) {
    throw new Error("Historical normalized SQLite snapshot no longer matches its receipt");
  }
  const database = createDatabaseConnection({
    filename: path,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  let schema: readonly unknown[];
  try {
    const integrity = checkDatabaseIntegrity(database);
    if (!integrity.ok || canonicalJson(integrity.messages.map((item) => item.toLowerCase())) !== canonicalJson(["ok"])) {
      throw new Error("Historical normalized SQLite snapshot failed quick_check");
    }
    if ((database.pragma("foreign_key_check") as unknown[]).length !== 0) {
      throw new Error("Historical normalized SQLite snapshot has foreign-key violations");
    }
    schema = database.prepare(`
      SELECT type, name, tbl_name, sql
      FROM sqlite_schema
      WHERE name NOT LIKE 'sqlite_%'
      ORDER BY type, name
    `).all() as readonly unknown[];
    const columns = database.pragma("table_info('storage')") as Array<{
      cid: number; name: string; type: string; notnull: number; dflt_value: unknown; pk: number;
    }>;
    const expectedColumns = [
      { cid: 0, name: "id", type: "INTEGER", notnull: 0, dflt_value: null, pk: 1 },
      { cid: 1, name: "value", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
    ];
    if (schema.length !== 1
      || (schema[0] as { type?: unknown }).type !== "table"
      || (schema[0] as { name?: unknown }).name !== "storage"
      || canonicalJson(columns) !== canonicalJson(expectedColumns)) {
      throw new Error("Historical SQLite snapshot is not the reviewed SQLMap storage schema");
    }
    const row = database.prepare("SELECT COUNT(*) AS count FROM storage").get() as { count: number };
    if (Number(row.count) !== 0) {
      throw new Error("Historical SQLMap snapshot contains rows and requires a separate semantic review");
    }
  } finally {
    database.close();
  }
  const after = stableFileFingerprint(path);
  if (canonicalJson(before) !== canonicalJson(after)) {
    throw new Error("Historical normalized SQLite snapshot changed during schema review");
  }
  return hashJson(schema!);
}

function assertPresentIdentity(
  current: HistoricalSqliteFileIdentity,
  receipt: HistoricalSqliteFileIdentity,
): asserts current is HistoricalSqlitePresentFileIdentity {
  if (!current.present || !receipt.present || canonicalJson(current) !== canonicalJson(receipt)) {
    throw new Error("Historical SQLite source file identity changed after snapshot review");
  }
}

/**
 * Convert one byte-hash-pinned snapshot receipt into an exact, content-free
 * quarantine mapping. Only the reviewed empty SQLMap storage schema is
 * admitted; any row, schema, source byte, identity, or snapshot change fails
 * closed and no historical source is rewritten.
 */
export async function loadHistoricalSqliteSnapshotQuarantineMapping(input: {
  readonly receipt: TrustedJsonFileReference;
  readonly allowedSourceRoots: readonly string[];
}): Promise<HistoricalSqliteSnapshotQuarantineMapping> {
  const loaded = loadTrustedJson(input.receipt, parseHistoricalSqliteSnapshotReceiptForQuarantine);
  const receipt = loaded.value;
  if (receipt.receiptPath !== loaded.receipt.sourcePath) {
    throw new Error("Historical SQLite receipt is bound to a different receipt path");
  }
  if (!input.allowedSourceRoots.some((root) => isInside(root, receipt.sourceAfter.canonicalDatabasePath))) {
    throw new Error("Historical SQLite receipt source is outside every configured source root");
  }
  const current = inspectHistoricalSqliteSource({
    sourceDatabasePath: receipt.sourceAfter.canonicalDatabasePath,
    sourceContainmentRoot: receipt.sourceAfter.containmentRoot,
    destinationPath: receipt.normalizedSnapshot.path,
    receiptPath: receipt.receiptPath,
  });
  if (current.sourceBundleSha256 !== receipt.sourceAfter.sourceBundleSha256) {
    throw new Error("Historical SQLite source bundle changed after snapshot review");
  }
  const normalizedSchemaFingerprint = validateEmptySqlmapSnapshot(
    receipt.normalizedSnapshot.path,
    receipt.normalizedSnapshot.sha256,
    receipt.normalizedSnapshot.sizeBytes,
  );
  const mappingId = `sqlite_quarantine_${hashJson({
    receiptSha256: loaded.receipt.sourceSha256,
    sourceBundleSha256: current.sourceBundleSha256,
    normalizedSnapshotSha256: receipt.normalizedSnapshot.sha256,
    normalizedSchemaFingerprint,
    semanticRowCount: 0,
  }).slice(0, 40)}`;
  const sourceFiles = (["database", "wal", "shm"] as const).flatMap((role) => {
    const currentFile = current.files[role];
    const receiptFile = receipt.sourceAfter.files[role];
    if (!currentFile.present || !receiptFile.present) {
      if (currentFile.present !== receiptFile.present) {
        throw new Error("Historical SQLite source sidecar presence changed after snapshot review");
      }
      return [];
    }
    assertPresentIdentity(currentFile, receiptFile);
    return [{
      role,
      path: currentFile.path,
      sha256: currentFile.sha256,
      byteSize: currentFile.sizeBytes,
      modifiedAt: currentFile.modifiedAt,
      sourceDevice: identityNumber(currentFile.device, `${role}.device`),
      sourceInode: identityNumber(currentFile.inode, `${role}.inode`),
      sourceModifiedTimeNanoseconds: currentFile.modifiedTimeNanoseconds,
      snapshotReceiptSha256: loaded.receipt.sourceSha256,
      normalizedSnapshotSha256: receipt.normalizedSnapshot.sha256,
      mappingId,
    } satisfies ReceiptBoundSqliteQuarantineFile];
  });
  if (sourceFiles.length < 1) throw new Error("Historical SQLite quarantine mapping has no source files");
  return Object.freeze({
    schemaVersion: HISTORICAL_SQLITE_SNAPSHOT_QUARANTINE_MAPPING_SCHEMA_VERSION,
    mappingId,
    disposition: "quarantined_no_semantic_records",
    reasonCode: "empty_sqlmap_storage_snapshot",
    snapshotId: receipt.snapshotId,
    snapshotReceiptSha256: loaded.receipt.sourceSha256,
    snapshotReceiptPayloadSha256: receipt.receiptPayloadSha256,
    sourceBundleSha256: current.sourceBundleSha256,
    normalizedSnapshotSha256: receipt.normalizedSnapshot.sha256,
    normalizedSnapshotBytes: receipt.normalizedSnapshot.sizeBytes,
    normalizedSchemaFingerprint,
    semanticRowCount: 0,
    sourceFiles: Object.freeze(sourceFiles),
  });
}

/** Verify the exact file again at each discovery boundary to close TOCTOU gaps. */
export function verifyReceiptBoundSqliteQuarantineFile(
  expected: ReceiptBoundSqliteQuarantineFile,
): void {
  const current = stableFileFingerprint(expected.path);
  if (current.sha256 !== expected.sha256
    || current.byteSize !== expected.byteSize
    || current.device !== String(expected.sourceDevice)
    || current.inode !== String(expected.sourceInode)
    || current.modifiedTimeNanoseconds !== expected.sourceModifiedTimeNanoseconds) {
    throw new Error("Receipt-bound SQLite source changed after quarantine mapping approval");
  }
}

export function indexHistoricalSqliteSnapshotQuarantineFiles(
  mappings: readonly HistoricalSqliteSnapshotQuarantineMapping[],
  allowedSourceRoots: readonly string[],
): ReadonlyMap<string, ReceiptBoundSqliteQuarantineFile> {
  const indexed = new Map<string, ReceiptBoundSqliteQuarantineFile>();
  for (const mapping of mappings) {
    if (mapping.disposition !== "quarantined_no_semantic_records" || mapping.semanticRowCount !== 0) {
      throw new Error("Only reviewed no-semantic-record SQLite mappings may bypass the active-source block");
    }
    for (const file of mapping.sourceFiles) {
      if (!allowedSourceRoots.some((root) => isInside(root, file.path))) {
        throw new Error("Receipt-bound SQLite source is outside every configured source root");
      }
      if (indexed.has(file.path)) throw new Error("Receipt-bound SQLite source is mapped more than once");
      verifyReceiptBoundSqliteQuarantineFile(file);
      indexed.set(file.path, file);
    }
  }
  return indexed;
}

export function summarizeHistoricalSqliteSnapshotQuarantineMappings(
  mappings: readonly HistoricalSqliteSnapshotQuarantineMapping[],
): {
  readonly mappings: number;
  readonly sourceFiles: number;
  readonly sourceBytes: number;
  readonly semanticRows: 0;
  readonly mappingSetHash: string;
  readonly disposition: "quarantined_no_semantic_records";
} {
  const files = mappings.flatMap(({ sourceFiles }) => sourceFiles);
  return {
    mappings: mappings.length,
    sourceFiles: files.length,
    sourceBytes: files.reduce((sum, file) => sum + file.byteSize, 0),
    semanticRows: 0,
    mappingSetHash: hashJson(mappings.map((mapping) => ({
      mappingId: mapping.mappingId,
      receiptSha256: mapping.snapshotReceiptSha256,
      sourceBundleSha256: mapping.sourceBundleSha256,
      normalizedSnapshotSha256: mapping.normalizedSnapshotSha256,
      normalizedSchemaFingerprint: mapping.normalizedSchemaFingerprint,
    })).sort((left, right) => left.mappingId.localeCompare(right.mappingId))),
    disposition: "quarantined_no_semantic_records",
  };
}
