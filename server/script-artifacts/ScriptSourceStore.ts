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

export interface StoredScriptSource {
  readonly storageUri: string;
  readonly byteSize: number;
}

export interface ScriptSourceStore {
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
