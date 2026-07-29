import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import { ScriptArtifactError } from "./types";

const SHA256 = /^[a-f0-9]{64}$/u;
const STORAGE_URI = /^ti-scale-script:\/\/sha256\/([a-f0-9]{64})$/u;
const SCRIPT_SOURCE_STORE_COMPOSITION_TTL_MS = 60_000;
const MAX_SCRIPT_SOURCE_STORE_COMPOSITION_LIFETIME_MS = 5 * 60_000;

export const SCRIPT_SOURCE_STORE_COMPOSITION_SCHEMA_VERSION =
  "ti-scale.script-source-store-composition.v1" as const;

export interface ScriptSourceStoreCompositionReceipt {
  readonly schemaVersion:
    typeof SCRIPT_SOURCE_STORE_COMPOSITION_SCHEMA_VERSION;
  readonly storeId: "file-content-addressed-v1" | "memory-test-content-addressed-v1";
  readonly configurationSha256: string;
  readonly immutableContentAddressed: true;
  readonly localFilesystem: boolean;
  readonly targetInteraction: false;
  readonly executionAuthority: "none";
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export interface StoredScriptSource {
  readonly storageUri: string;
  readonly byteSize: number;
}

export interface ScriptSourceStore {
  inspectComposition(now?: Date): ScriptSourceStoreCompositionReceipt;
  put(contentHash: string, source: string): StoredScriptSource;
  read(storageUri: string, expectedContentHash: string): string;
}

function digest(source: string): string {
  return createHash("sha256").update(source, "utf8").digest("hex");
}

function assertedHash(value: string): string {
  if (!SHA256.test(value)) {
    throw new ScriptArtifactError("invalid_script_content_hash", "Script content hash must be a lowercase SHA-256 digest");
  }
  return value;
}

function storageUri(hash: string): string {
  return `ti-scale-script://sha256/${hash}`;
}

function sourceStoreReceipt(
  input: Readonly<{
    storeId: ScriptSourceStoreCompositionReceipt["storeId"];
    configurationSha256: string;
    localFilesystem: boolean;
    now: Date;
  }>,
): ScriptSourceStoreCompositionReceipt {
  if (!Number.isFinite(input.now.getTime()) || !SHA256.test(input.configurationSha256)) {
    throw new ScriptArtifactError(
      "script_source_integrity_failure",
      "Script source store composition identity is invalid",
      "data_integrity",
      500,
    );
  }
  const unsigned = Object.freeze({
    schemaVersion: SCRIPT_SOURCE_STORE_COMPOSITION_SCHEMA_VERSION,
    storeId: input.storeId,
    configurationSha256: input.configurationSha256,
    immutableContentAddressed: true as const,
    localFilesystem: input.localFilesystem,
    targetInteraction: false as const,
    executionAuthority: "none" as const,
    observedAt: input.now.toISOString(),
    expiresAt: new Date(
      input.now.getTime() + SCRIPT_SOURCE_STORE_COMPOSITION_TTL_MS,
    ).toISOString(),
  });
  return Object.freeze({
    ...unsigned,
    receiptSha256: createHash("sha256")
      .update(JSON.stringify(unsigned), "utf8")
      .digest("hex"),
  });
}

export function scriptSourceStoreCompositionReceiptValid(
  receipt: ScriptSourceStoreCompositionReceipt,
  now = new Date(),
): boolean {
  try {
    const { receiptSha256, ...unsigned } = receipt;
    const observedAt = Date.parse(receipt.observedAt);
    const expiresAt = Date.parse(receipt.expiresAt);
    return receipt.schemaVersion === SCRIPT_SOURCE_STORE_COMPOSITION_SCHEMA_VERSION
      && ["file-content-addressed-v1", "memory-test-content-addressed-v1"]
        .includes(receipt.storeId)
      && SHA256.test(receipt.configurationSha256)
      && receipt.immutableContentAddressed === true
      && typeof receipt.localFilesystem === "boolean"
      && receipt.targetInteraction === false
      && receipt.executionAuthority === "none"
      && Number.isFinite(observedAt)
      && Number.isFinite(expiresAt)
      && new Date(observedAt).toISOString() === receipt.observedAt
      && new Date(expiresAt).toISOString() === receipt.expiresAt
      && observedAt <= now.getTime()
      && expiresAt > now.getTime()
      && expiresAt > observedAt
      && expiresAt - observedAt
        <= MAX_SCRIPT_SOURCE_STORE_COMPOSITION_LIFETIME_MS
      && SHA256.test(receiptSha256)
      && receiptSha256 === createHash("sha256")
        .update(JSON.stringify(unsigned), "utf8")
        .digest("hex");
  } catch {
    return false;
  }
}

/**
 * Immutable, content-addressed local source store. User-controlled names never
 * participate in filesystem resolution; only a validated SHA-256 digest does.
 */
export class FileScriptSourceStore implements ScriptSourceStore {
  private readonly root: string;

  constructor(root: string) {
    if (!root.trim() || !isAbsolute(root)) {
      throw new ScriptArtifactError(
        "unsafe_script_store_path",
        "Script source storage root must be an explicit absolute path",
      );
    }
    this.root = resolve(root);
    mkdirSync(this.root, { recursive: true, mode: 0o700 });
    if (realpathSync(this.root) !== this.root) {
      throw new ScriptArtifactError("unsafe_script_store_path", "Script source storage root cannot traverse symbolic links");
    }
    const metadata = lstatSync(this.root);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new ScriptArtifactError("unsafe_script_store_path", "Script source storage root must be a real directory");
    }
    chmodSync(this.root, 0o700);
  }

  inspectComposition(now = new Date()): ScriptSourceStoreCompositionReceipt {
    if (realpathSync(this.root) !== this.root) {
      throw new ScriptArtifactError(
        "unsafe_script_store_path",
        "Script source storage root cannot traverse symbolic links",
      );
    }
    const metadata = lstatSync(this.root);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new ScriptArtifactError(
        "unsafe_script_store_path",
        "Script source storage root must be a real directory",
      );
    }
    return sourceStoreReceipt({
      storeId: "file-content-addressed-v1",
      configurationSha256: createHash("sha256")
        .update(this.root, "utf8")
        .digest("hex"),
      localFilesystem: true,
      now,
    });
  }

  put(contentHash: string, source: string): StoredScriptSource {
    const hash = assertedHash(contentHash);
    if (digest(source) !== hash) {
      throw new ScriptArtifactError("script_source_hash_mismatch", "Script source does not match its computed content hash");
    }
    const bytes = Buffer.from(source, "utf8");
    const directory = this.safePath(hash.slice(0, 2));
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const directoryMetadata = lstatSync(directory);
    if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
      throw new ScriptArtifactError("unsafe_script_store_path", "Script source shard is not a real directory");
    }
    const destination = this.safePath(hash.slice(0, 2), hash);
    if (existsSync(destination)) {
      this.assertStoredFile(destination, hash);
      return { storageUri: storageUri(hash), byteSize: bytes.length };
    }

    const temporary = this.safePath(hash.slice(0, 2), `.${hash}.${randomUUID()}.tmp`);
    try {
      writeFileSync(temporary, bytes, { encoding: "utf8", flag: "wx", mode: 0o600 });
      try {
        linkSync(temporary, destination);
      } catch (error) {
        const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
        if (code !== "EEXIST") throw error;
      }
    } finally {
      if (existsSync(temporary)) unlinkSync(temporary);
    }
    this.assertStoredFile(destination, hash);
    return { storageUri: storageUri(hash), byteSize: bytes.length };
  }

  read(value: string, expectedContentHash: string): string {
    const expected = assertedHash(expectedContentHash);
    const match = STORAGE_URI.exec(value);
    if (!match || match[1] !== expected) {
      throw new ScriptArtifactError("invalid_script_storage_uri", "Script storage reference does not match its immutable content hash", "data_integrity", 500);
    }
    const sourcePath = this.safePath(expected.slice(0, 2), expected);
    this.assertStoredFile(sourcePath, expected);
    return readFileSync(sourcePath, "utf8");
  }

  private safePath(...segments: readonly string[]): string {
    const candidate = resolve(join(this.root, ...segments));
    if (candidate !== this.root && !candidate.startsWith(`${this.root}${sep}`)) {
      throw new ScriptArtifactError("unsafe_script_store_path", "Script source path escaped its configured storage root");
    }
    return candidate;
  }

  private assertStoredFile(path: string, expectedHash: string): void {
    if (!existsSync(path)) {
      throw new ScriptArtifactError("script_source_missing", "Canonical script source is missing from the artifact store", "data_integrity", 500);
    }
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new ScriptArtifactError("unsafe_script_store_path", "Canonical script source is not a regular file", "data_integrity", 500);
    }
    const actual = createHash("sha256").update(readFileSync(path)).digest("hex");
    if (actual !== expectedHash) {
      throw new ScriptArtifactError("script_source_integrity_failure", "Canonical script source failed SHA-256 verification", "data_integrity", 500);
    }
  }
}

/** Deterministic in-memory content-addressed store for service and router tests. */
export class MemoryScriptSourceStore implements ScriptSourceStore {
  private readonly sources = new Map<string, string>();

  inspectComposition(now = new Date()): ScriptSourceStoreCompositionReceipt {
    return sourceStoreReceipt({
      storeId: "memory-test-content-addressed-v1",
      configurationSha256: createHash("sha256")
        .update("ti-scale:memory-script-source-store:v1", "utf8")
        .digest("hex"),
      localFilesystem: false,
      now,
    });
  }

  put(contentHash: string, source: string): StoredScriptSource {
    const hash = assertedHash(contentHash);
    if (digest(source) !== hash) {
      throw new ScriptArtifactError("script_source_hash_mismatch", "Script source does not match its computed content hash");
    }
    const existing = this.sources.get(hash);
    if (existing !== undefined && existing !== source) {
      throw new ScriptArtifactError("script_source_integrity_failure", "Content-addressed script source collision detected", "data_integrity", 500);
    }
    this.sources.set(hash, source);
    return { storageUri: storageUri(hash), byteSize: Buffer.byteLength(source, "utf8") };
  }

  read(value: string, expectedContentHash: string): string {
    const expected = assertedHash(expectedContentHash);
    const match = STORAGE_URI.exec(value);
    if (!match || match[1] !== expected) {
      throw new ScriptArtifactError("invalid_script_storage_uri", "Script storage reference does not match its immutable content hash", "data_integrity", 500);
    }
    const source = this.sources.get(expected);
    if (source === undefined || digest(source) !== expected) {
      throw new ScriptArtifactError("script_source_missing", "Canonical script source is missing from the artifact store", "data_integrity", 500);
    }
    return source;
  }
}
