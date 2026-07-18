import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  chmod as chmodAsync,
  lstat as lstatAsync,
  link as linkAsync,
  open as openAsync,
  readFile as readFileAsync,
  rename as renameAsync,
  unlink as unlinkAsync,
} from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { createHash, randomUUID } from "node:crypto";

export interface AtomicWriteExpectation {
  readonly exists: boolean;
  /** SHA-256 of the exact destination bytes observed during bridge preflight. */
  readonly sha256?: string;
  /** Re-check canonical policy/version after fsync and immediately before rename. */
  readonly beforeRename?: () => void | Promise<void>;
  /** Testable no-clobber seam after the old destination is captured. */
  readonly beforePublish?: () => void | Promise<void>;
}

export class VaultDestinationChangedError extends Error {
  constructor() {
    super("Vault note changed while an atomic projection was being prepared");
    this.name = "VaultDestinationChangedError";
  }
}

export class VaultRoundTripHealthError extends Error {
  constructor(options?: ErrorOptions) {
    super("Vault filesystem round-trip health check failed", options);
    this.name = "VaultRoundTripHealthError";
  }
}

export interface VaultRoundTripHealth {
  readonly vaultRoot: string;
  readonly checks: {
    readonly write: true;
    readonly read: true;
    readonly rename: true;
    readonly delete: true;
  };
}

function isWithin(root: string, candidate: string): boolean {
  const result = relative(root, candidate);
  return result === "" || (!result.startsWith(`..${sep}`) && result !== ".." && !isAbsolute(result));
}

function assertNoSymlinkPath(root: string, target: string): void {
  const pathFromRoot = relative(root, target);
  if (!isWithin(root, target)) throw new Error("Vault path escapes its configured root");
  let current = root;
  for (const segment of pathFromRoot.split(sep).filter(Boolean)) {
    current = resolve(current, segment);
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
      throw new Error("Symbolic links are not permitted in managed vault paths");
    }
  }
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === "object" && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function fsyncDirectorySync(path: string): void {
  const descriptor = openSync(path, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

async function fsyncDirectory(path: string): Promise<void> {
  const handle = await openAsync(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Restricts every vault access to one explicitly configured filesystem root. */
export class VaultPathPolicy {
  readonly allowedRoot: string;

  constructor(allowedRoot: string) {
    if (!isAbsolute(allowedRoot)) throw new TypeError("Vault sandbox root must be absolute");
    mkdirSync(allowedRoot, { recursive: true, mode: 0o700 });
    this.allowedRoot = realpathSync(allowedRoot);
  }

  resolveVault(vaultPath: string): string {
    if (!vaultPath.trim() || vaultPath.includes("\0")) throw new TypeError("Vault path is invalid");
    const candidate = resolve(this.allowedRoot, vaultPath);
    if (!isWithin(this.allowedRoot, candidate)) throw new Error("Vault path escapes its configured root");
    assertNoSymlinkPath(this.allowedRoot, candidate);
    mkdirSync(candidate, { recursive: true, mode: 0o700 });
    assertNoSymlinkPath(this.allowedRoot, candidate);
    return realpathSync(candidate);
  }

  /**
   * Resolve an already configured vault for read-only work without creating a
   * missing directory. This keeps download attempts free of filesystem writes.
   */
  resolveExistingVault(vaultPath: string): string {
    if (!vaultPath.trim() || vaultPath.includes("\0")) throw new TypeError("Vault path is invalid");
    const candidate = resolve(this.allowedRoot, vaultPath);
    if (!isWithin(this.allowedRoot, candidate)) throw new Error("Vault path escapes its configured root");
    assertNoSymlinkPath(this.allowedRoot, candidate);
    if (!existsSync(candidate) || !lstatSync(candidate).isDirectory()) {
      throw new Error("Configured vault is not an existing directory");
    }
    const verified = realpathSync(candidate);
    if (!isWithin(this.allowedRoot, verified)) throw new Error("Vault is outside its configured root");
    return verified;
  }

  resolveRelative(vaultRoot: string, relativePath: string, createParent = false): string {
    if (!relativePath.trim() || relativePath.includes("\0") || isAbsolute(relativePath)) {
      throw new TypeError("Vault note path must be a non-empty relative path");
    }
    const verifiedVault = realpathSync(vaultRoot);
    if (!isWithin(this.allowedRoot, verifiedVault)) throw new Error("Vault is outside its configured root");
    const target = resolve(verifiedVault, relativePath);
    if (!isWithin(verifiedVault, target)) throw new Error("Vault note path traversal is not permitted");
    assertNoSymlinkPath(verifiedVault, target);
    if (createParent) {
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      assertNoSymlinkPath(verifiedVault, dirname(target));
    }
    return target;
  }

  /**
   * Prove that a candidate vault can perform the complete bounded filesystem
   * lifecycle required by projection. The randomized health directory is
   * always inside the configured root and is removed before success returns.
   */
  verifyRoundTrip(vaultPath: string): VaultRoundTripHealth {
    const vaultRoot = this.resolveVault(vaultPath);
    return this.#verifyRoundTripAt(vaultRoot);
  }

  /** Run the same proof for a configured Vault without creating it when the
   * path is missing. This is the fail-closed recovery/offline boundary. */
  verifyExistingRoundTrip(vaultPath: string): VaultRoundTripHealth {
    const vaultRoot = this.resolveExistingVault(vaultPath);
    return this.#verifyRoundTripAt(vaultRoot);
  }

  #verifyRoundTripAt(vaultRoot: string): VaultRoundTripHealth {
    const nonce = randomUUID();
    const relativeDirectory = `.ti-scale-health-${nonce}`;
    const healthDirectory = this.resolveRelative(vaultRoot, relativeDirectory);
    const source = this.resolveRelative(vaultRoot, `${relativeDirectory}/write-${nonce}.tmp`);
    const renamed = this.resolveRelative(vaultRoot, `${relativeDirectory}/renamed-${nonce}.tmp`);
    const marker = `ti-scale-vault-health:${nonce}`;
    let descriptor: number | undefined;
    let completed = false;
    try {
      mkdirSync(healthDirectory, { mode: 0o700 });
      descriptor = openSync(source, "wx", 0o600);
      writeFileSync(descriptor, marker, "utf8");
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      if (readFileSync(source, "utf8") !== marker) throw new Error("Vault health read did not match its write");
      renameSync(source, renamed);
      fsyncDirectorySync(healthDirectory);
      if (readFileSync(renamed, "utf8") !== marker) throw new Error("Vault health rename did not preserve content");
      unlinkSync(renamed);
      fsyncDirectorySync(healthDirectory);
      // This directory is intentionally empty after the delete proof. Use the
      // directory-specific syscall; Bun 1.3.14 can return EFAULT for rmSync on
      // an empty directory when no recursive options are supplied.
      rmdirSync(healthDirectory);
      fsyncDirectorySync(vaultRoot);
      if (existsSync(healthDirectory) || existsSync(source) || existsSync(renamed)) {
        throw new Error("Vault health cleanup did not remove temporary resources");
      }
      completed = true;
      return {
        vaultRoot,
        checks: { write: true, read: true, rename: true, delete: true },
      };
    } catch (error) {
      throw new VaultRoundTripHealthError({ cause: error });
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      if (!completed) {
        // All cleanup targets were resolved through the sandbox policy above.
        // Failure to remove them keeps the health check failed and leaves no
        // opportunity to report the candidate as connected.
        rmSync(healthDirectory, { recursive: true, force: true });
      }
    }
  }

  atomicWrite(
    vaultRoot: string,
    relativePath: string,
    content: string,
    expectation?: AtomicWriteExpectation,
  ): string {
    return this.atomicWriteBytes(vaultRoot, relativePath, Buffer.from(content, "utf8"), expectation);
  }

  atomicWriteBytes(
    vaultRoot: string,
    relativePath: string,
    content: Uint8Array,
    expectation?: AtomicWriteExpectation,
  ): string {
    const destination = this.resolveRelative(vaultRoot, relativePath, true);
    const temporary = `${destination}.tmp-${randomUUID()}`;
    let descriptor: number | undefined;
    try {
      descriptor = openSync(temporary, "wx", 0o600);
      writeFileSync(descriptor, content);
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      chmodSync(temporary, 0o600);
      if (expectation) {
        this.#publishExpectedSync(vaultRoot, relativePath, temporary, expectation);
      } else {
        renameSync(temporary, destination);
        chmodSync(destination, 0o600);
      }
      return destination;
    } catch (error) {
      if (descriptor !== undefined) closeSync(descriptor);
      if (existsSync(temporary)) unlinkSync(temporary);
      throw error;
    }
  }

  /**
   * Async equivalent of atomicWriteBytes for bounded-concurrency bulk export.
   * The file is still individually fsynced before rename. A destination
   * expectation prevents a human edit made during the async fsync window from
   * being overwritten.
   */
  async atomicWriteAsync(
    vaultRoot: string,
    relativePath: string,
    content: string,
    expectation: AtomicWriteExpectation,
  ): Promise<string> {
    return this.atomicWriteBytesAsync(
      vaultRoot,
      relativePath,
      Buffer.from(content, "utf8"),
      expectation,
    );
  }

  async atomicWriteBytesAsync(
    vaultRoot: string,
    relativePath: string,
    content: Uint8Array,
    expectation: AtomicWriteExpectation,
  ): Promise<string> {
    if (expectation.exists && !/^[a-f0-9]{64}$/u.test(expectation.sha256 ?? "")) {
      throw new TypeError("Existing vault write expectations require a SHA-256 digest");
    }
    if (!expectation.exists && expectation.sha256 !== undefined) {
      throw new TypeError("Missing vault write expectations cannot include a digest");
    }
    const destination = this.resolveRelative(vaultRoot, relativePath, true);
    const temporary = `${destination}.tmp-${randomUUID()}`;
    let handle: Awaited<ReturnType<typeof openAsync>> | undefined;
    try {
      handle = await openAsync(temporary, "wx", 0o600);
      await handle.writeFile(content);
      await handle.sync();
      await handle.close();
      handle = undefined;
      await chmodAsync(temporary, 0o600);

      await this.#publishExpected(vaultRoot, relativePath, temporary, expectation);
      return destination;
    } catch (error) {
      if (handle) await handle.close().catch(() => undefined);
      await unlinkAsync(temporary).catch(() => undefined);
      throw error;
    }
  }

  #writeGuardPath(vaultRoot: string, relativePath: string): string {
    const digest = createHash("sha256").update(relativePath, "utf8").digest("hex");
    return this.resolveRelative(vaultRoot, `.ti-scale/write-guards/${digest}.guard`, true);
  }

  #quarantineStaleGuardSync(vaultRoot: string, guard: string): void {
    const quarantine = this.resolveRelative(
      vaultRoot,
      `.ti-scale/quarantine/recovered-write-guard-${randomUUID()}.guard`,
      true,
    );
    renameSync(guard, quarantine);
    fsyncDirectorySync(dirname(quarantine));
  }

  async #quarantineStaleGuard(vaultRoot: string, guard: string): Promise<void> {
    const quarantine = this.resolveRelative(
      vaultRoot,
      `.ti-scale/quarantine/recovered-write-guard-${randomUUID()}.guard`,
      true,
    );
    await renameAsync(guard, quarantine);
    await fsyncDirectory(dirname(quarantine));
  }

  #recoverStaleGuardSync(vaultRoot: string, destination: string, guard: string): void {
    if (!existsSync(guard)) return;
    const metadata = lstatSync(guard);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new VaultDestinationChangedError();
    }
    if (existsSync(destination)) {
      this.#quarantineStaleGuardSync(vaultRoot, guard);
      throw new VaultDestinationChangedError();
    }
    linkSync(guard, destination);
    fsyncDirectorySync(dirname(destination));
    unlinkSync(guard);
    fsyncDirectorySync(dirname(guard));
    throw new VaultDestinationChangedError();
  }

  async #recoverStaleGuard(
    vaultRoot: string,
    destination: string,
    guard: string,
  ): Promise<void> {
    if (!existsSync(guard)) return;
    const metadata = await lstatAsync(guard);
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw new VaultDestinationChangedError();
    }
    if (existsSync(destination)) {
      await this.#quarantineStaleGuard(vaultRoot, guard);
      throw new VaultDestinationChangedError();
    }
    await linkAsync(guard, destination);
    await fsyncDirectory(dirname(destination));
    await unlinkAsync(guard);
    await fsyncDirectory(dirname(guard));
    throw new VaultDestinationChangedError();
  }

  #restoreCapturedDestinationSync(destination: string, guard: string): void {
    if (!existsSync(destination)) {
      linkSync(guard, destination);
      fsyncDirectorySync(dirname(destination));
      unlinkSync(guard);
      fsyncDirectorySync(dirname(guard));
    }
  }

  async #restoreCapturedDestination(destination: string, guard: string): Promise<void> {
    if (!existsSync(destination)) {
      await linkAsync(guard, destination);
      await fsyncDirectory(dirname(destination));
      await unlinkAsync(guard);
      await fsyncDirectory(dirname(guard));
    }
  }

  #assertExpectedDestinationSync(destination: string, expectation: AtomicWriteExpectation): void {
    const destinationExists = existsSync(destination);
    if (destinationExists !== expectation.exists) throw new VaultDestinationChangedError();
    if (!destinationExists) return;
    const metadata = lstatSync(destination);
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new VaultDestinationChangedError();
    if (sha256Bytes(readFileSync(destination)) !== expectation.sha256) {
      throw new VaultDestinationChangedError();
    }
  }

  async #assertExpectedDestination(destination: string, expectation: AtomicWriteExpectation): Promise<void> {
    const destinationExists = existsSync(destination);
    if (destinationExists !== expectation.exists) throw new VaultDestinationChangedError();
    if (!destinationExists) return;
    const metadata = await lstatAsync(destination);
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new VaultDestinationChangedError();
    if (sha256Bytes(await readFileAsync(destination)) !== expectation.sha256) {
      throw new VaultDestinationChangedError();
    }
  }

  #runSyncHook(hook: (() => void | Promise<void>) | undefined): void {
    const result = hook?.();
    if (result && typeof (result as Promise<void>).then === "function") {
      throw new TypeError("Synchronous atomic writes require synchronous publication guards");
    }
  }

  #publishExpectedSync(
    vaultRoot: string,
    relativePath: string,
    temporary: string,
    expectation: AtomicWriteExpectation,
  ): void {
    const destination = this.resolveRelative(vaultRoot, relativePath, true);
    const guard = this.#writeGuardPath(vaultRoot, relativePath);
    this.#recoverStaleGuardSync(vaultRoot, destination, guard);
    this.#assertExpectedDestinationSync(destination, expectation);
    this.#runSyncHook(expectation.beforeRename);
    if (!expectation.exists) {
      this.#runSyncHook(expectation.beforePublish);
      try {
        linkSync(temporary, destination);
      } catch (error) {
        if (errorCode(error) === "EEXIST") throw new VaultDestinationChangedError();
        throw error;
      }
      fsyncDirectorySync(dirname(destination));
      unlinkSync(temporary);
      fsyncDirectorySync(dirname(temporary));
      return;
    }

    renameSync(destination, guard);
    try {
      const guardMetadata = lstatSync(guard);
      if (guardMetadata.isSymbolicLink() || !guardMetadata.isFile()
          || sha256Bytes(readFileSync(guard)) !== expectation.sha256) {
        this.#restoreCapturedDestinationSync(destination, guard);
        throw new VaultDestinationChangedError();
      }
      this.#runSyncHook(expectation.beforePublish);
      try {
        linkSync(temporary, destination);
      } catch (error) {
        if (errorCode(error) === "EEXIST") {
          this.#quarantineStaleGuardSync(vaultRoot, guard);
          throw new VaultDestinationChangedError();
        }
        throw error;
      }
      fsyncDirectorySync(dirname(destination));
      unlinkSync(temporary);
      unlinkSync(guard);
      fsyncDirectorySync(dirname(destination));
      fsyncDirectorySync(dirname(guard));
    } catch (error) {
      this.#restoreCapturedDestinationSync(destination, guard);
      throw error;
    }
  }

  async #publishExpected(
    vaultRoot: string,
    relativePath: string,
    temporary: string,
    expectation: AtomicWriteExpectation,
  ): Promise<void> {
    const destination = this.resolveRelative(vaultRoot, relativePath, true);
    const guard = this.#writeGuardPath(vaultRoot, relativePath);
    await this.#recoverStaleGuard(vaultRoot, destination, guard);
    await this.#assertExpectedDestination(destination, expectation);
    await expectation.beforeRename?.();
    if (!expectation.exists) {
      await expectation.beforePublish?.();
      try {
        await linkAsync(temporary, destination);
      } catch (error) {
        if (errorCode(error) === "EEXIST") throw new VaultDestinationChangedError();
        throw error;
      }
      await fsyncDirectory(dirname(destination));
      await unlinkAsync(temporary);
      await fsyncDirectory(dirname(temporary));
      return;
    }

    await renameAsync(destination, guard);
    try {
      const guardMetadata = await lstatAsync(guard);
      if (guardMetadata.isSymbolicLink() || !guardMetadata.isFile()
          || sha256Bytes(await readFileAsync(guard)) !== expectation.sha256) {
        await this.#restoreCapturedDestination(destination, guard);
        throw new VaultDestinationChangedError();
      }
      await expectation.beforePublish?.();
      try {
        await linkAsync(temporary, destination);
      } catch (error) {
        if (errorCode(error) === "EEXIST") {
          await this.#quarantineStaleGuard(vaultRoot, guard);
          throw new VaultDestinationChangedError();
        }
        throw error;
      }
      await fsyncDirectory(dirname(destination));
      await unlinkAsync(temporary);
      await unlinkAsync(guard);
      await fsyncDirectory(dirname(destination));
      await fsyncDirectory(dirname(guard));
    } catch (error) {
      await this.#restoreCapturedDestination(destination, guard);
      throw error;
    }
  }
}

export function safeVaultSegment(value: string, fallback: string): string {
  const normalized = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[<>:"/\\|?*\u0000-\u001F]/g, "-")
    .replace(/\.{2,}/g, "-")
    .replace(/[^A-Za-z0-9._ -]+/g, "-")
    .replace(/[. ]+$/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .slice(0, 96)
    .toLowerCase();
  return normalized && normalized !== "." && normalized !== ".." ? normalized : fallback;
}
