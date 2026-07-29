import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export interface OperatorTokenEnvironment {
  readonly [name: string]: string | undefined;
  readonly TI_SCALE_OPERATOR_TOKEN?: string;
  readonly TI_SCALE_OPERATOR_TOKEN_FILE?: string;
}

function validateToken(value: string): string {
  if (Buffer.byteLength(value, "utf8") < 24) {
    throw new Error("Ti-Scale operator token must contain at least 24 bytes");
  }
  if (Buffer.byteLength(value, "utf8") > 4_096 || /[\0\r\n]/u.test(value)) {
    throw new Error("Ti-Scale operator token must be one bounded line without control separators");
  }
  return value;
}

/** Resolve one local operator secret without requiring it in a process environment. */
export function resolveOperatorToken(
  environment: OperatorTokenEnvironment = process.env,
): string | undefined {
  const inline = environment.TI_SCALE_OPERATOR_TOKEN?.trim();
  const configuredFile = environment.TI_SCALE_OPERATOR_TOKEN_FILE?.trim();
  if (inline && configuredFile) {
    throw new Error("Configure TI_SCALE_OPERATOR_TOKEN or TI_SCALE_OPERATOR_TOKEN_FILE, not both");
  }
  if (inline) return validateToken(inline);
  if (!configuredFile) return undefined;
  if (!isAbsolute(configuredFile)) {
    throw new Error("TI_SCALE_OPERATOR_TOKEN_FILE must be an absolute path");
  }
  const path = resolve(configuredFile);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("TI_SCALE_OPERATOR_TOKEN_FILE must be a regular file, not a link");
  }
  if (metadata.size < 24 || metadata.size > 4_097) {
    throw new Error("TI_SCALE_OPERATOR_TOKEN_FILE has an invalid bounded size");
  }
  const systemdCredential = path.startsWith("/run/credentials/");
  if (!systemdCredential && (metadata.mode & 0o077) !== 0) {
    throw new Error("TI_SCALE_OPERATOR_TOKEN_FILE must not be accessible to group or other users");
  }
  const raw = readFileSync(path, "utf8");
  const value = raw.endsWith("\n") ? raw.slice(0, -1) : raw;
  return validateToken(value);
}
