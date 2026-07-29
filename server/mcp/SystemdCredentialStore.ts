import {
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";

const CREDENTIAL_ID = /^[A-Za-z0-9_.-]{1,128}$/u;
const MAX_CREDENTIAL_BYTES = 4 * 1024;

export class SystemdCredentialStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SystemdCredentialStoreError";
  }
}

function validatedDirectory(path: string): string {
  if (!isAbsolute(path)) {
    throw new SystemdCredentialStoreError("The systemd credential directory must be absolute");
  }
  const normalized = resolve(path);
  let metadata;
  try {
    metadata = lstatSync(normalized);
  } catch {
    throw new SystemdCredentialStoreError("The systemd credential directory is unavailable");
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new SystemdCredentialStoreError("The systemd credential directory is invalid");
  }
  if (realpathSync(normalized) !== normalized) {
    throw new SystemdCredentialStoreError("The systemd credential directory must not traverse symbolic links");
  }
  return normalized;
}

function credentialPath(directory: string, id: string): string {
  if (!CREDENTIAL_ID.test(id)) {
    throw new SystemdCredentialStoreError("The systemd credential identifier is invalid");
  }
  const path = resolve(directory, id);
  if (!path.startsWith(`${directory}${sep}`)) {
    throw new SystemdCredentialStoreError("The systemd credential path escaped its private directory");
  }
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch {
    throw new SystemdCredentialStoreError("The requested systemd credential is unavailable");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new SystemdCredentialStoreError("The requested systemd credential is invalid");
  }
  if (metadata.size < 1 || metadata.size > MAX_CREDENTIAL_BYTES + 1) {
    throw new SystemdCredentialStoreError("The requested systemd credential has an invalid size");
  }
  return path;
}

/**
 * Reads only systemd's private credential mount. It never accepts a secret
 * value from an environment variable or from an MCP connection descriptor.
 */
export class SystemdCredentialStore {
  readonly directory: string;

  constructor(directory: string) {
    this.directory = validatedDirectory(directory);
  }

  read(id: string): Uint8Array {
    const raw = readFileSync(credentialPath(this.directory, id));
    const withoutNewline = raw.at(-1) === 0x0a
      ? raw.subarray(0, raw.at(-2) === 0x0d ? raw.byteLength - 2 : raw.byteLength - 1)
      : raw;
    if (
      withoutNewline.byteLength < 1
      || withoutNewline.byteLength > MAX_CREDENTIAL_BYTES
      || withoutNewline.includes(0)
      || [...withoutNewline].some((byte) => byte < 0x20 || byte === 0x7f)
    ) {
      raw.fill(0);
      throw new SystemdCredentialStoreError("The requested systemd credential has an invalid value");
    }
    const result = new Uint8Array(withoutNewline);
    raw.fill(0);
    return result;
  }

  has(id: string): boolean {
    try {
      const credential = this.read(id);
      credential.fill(0);
      return true;
    } catch {
      return false;
    }
  }
}

export function systemdCredentialStoreFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): SystemdCredentialStore | undefined {
  const directory = environment.CREDENTIALS_DIRECTORY?.trim();
  return directory ? new SystemdCredentialStore(directory) : undefined;
}
