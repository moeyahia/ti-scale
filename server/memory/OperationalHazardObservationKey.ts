import { constants, closeSync, lstatSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { isAbsolute, resolve } from "node:path";

const MINIMUM_KEY_BYTES = 32;
const MAXIMUM_FILE_BYTES = 4_097;

export interface OperationalHazardObservationKeyEnvironment {
  readonly [name: string]: string | undefined;
  readonly TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY?: string;
  readonly TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE?: string;
}

function validate(value: string, source: string): Buffer {
  if (/[\r\n\0]/u.test(value)) {
    throw new Error(`${source} must be one bounded line`);
  }
  const key = Buffer.from(value, "utf8");
  if (key.byteLength < MINIMUM_KEY_BYTES || key.byteLength > 4_096) {
    throw new Error(`${source} must contain between 32 and 4096 bytes`);
  }
  return key;
}

function readPrivateKeyFile(path: string, label: string): Buffer {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a private regular file, not a link`);
  }
  if (metadata.size < MINIMUM_KEY_BYTES || metadata.size > MAXIMUM_FILE_BYTES) {
    throw new Error(`${label} has an invalid bounded size`);
  }
  if (!path.startsWith("/run/credentials/") && (metadata.mode & 0o077) !== 0) {
    throw new Error(`${label} must not be accessible to group or other users`);
  }
  const raw = readFileSync(path, "utf8");
  return validate(raw.endsWith("\n") ? raw.slice(0, -1) : raw, label);
}

/**
 * Loads a stable server-only HMAC key. When no managed credential is supplied,
 * the standalone local product creates a mode-0600 companion file beside its
 * canonical database. The key is never returned by an HTTP contract.
 */
export function resolveOperationalHazardObservationKey(input: {
  readonly databasePath: string;
  readonly environment?: OperationalHazardObservationKeyEnvironment;
}): Buffer {
  const environment = input.environment ?? process.env;
  const inline = environment.TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY;
  const configuredFile = environment.TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE?.trim();
  if (inline && configuredFile) {
    throw new Error(
      "Configure TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY or TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE, not both",
    );
  }
  if (inline) return validate(inline, "TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY");

  const path = configuredFile
    ? (() => {
        if (!isAbsolute(configuredFile)) {
          throw new Error("TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE must be an absolute path");
        }
        return resolve(configuredFile);
      })()
    : resolve(`${input.databasePath}.operational-hazard-hmac`);

  try {
    return readPrivateKeyFile(path, "Operational-hazard HMAC key file");
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? String((error as { readonly code?: unknown }).code)
      : "";
    if (configuredFile || code !== "ENOENT") throw error;
  }

  const value = randomBytes(48).toString("base64url");
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    writeFileSync(descriptor, `${value}\n`, { encoding: "utf8" });
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? String((error as { readonly code?: unknown }).code)
      : "";
    if (code !== "EEXIST") throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  return readPrivateKeyFile(path, "Operational-hazard HMAC key file");
}
