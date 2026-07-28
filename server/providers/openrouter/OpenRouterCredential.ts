import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { OpenRouterPlanningError } from "./types";

const MAXIMUM_CREDENTIAL_BYTES = 8 * 1024;
const ALLOWED_FILE_MODES = new Set([0o400, 0o600]);

export interface OpenRouterCredentialOptions {
  readonly path: string;
  /** Defaults to the current effective uid. Root and this service uid are the only accepted owners. */
  readonly serviceUid?: number;
}

/** A process-local startup snapshot; callers must never serialize its result. */
export type OpenRouterCredentialReader = () => string;

function credentialError(code: string, message: string): OpenRouterPlanningError {
  return new OpenRouterPlanningError(code, message, {
    status: 503,
    category: "authentication_missing",
    retryable: false,
    remediation: "Provision a private root- or service-owned OpenRouter credential file and retry readiness.",
  });
}

function serviceUid(value: number | undefined): number {
  const resolved = value ?? (typeof process.geteuid === "function" ? process.geteuid() : -1);
  if (!Number.isSafeInteger(resolved) || resolved < 0) {
    throw credentialError("openrouter_credential_owner_unknown", "The OpenRouter credential owner cannot be verified");
  }
  return resolved;
}

function acceptedOwner(uid: number, expectedServiceUid: number): boolean {
  return uid === 0 || uid === expectedServiceUid;
}

/**
 * Read a credential through O_NOFOLLOW after validating its private ownership.
 * The returned value is never stored by the client and must not be logged.
 */
export function readOpenRouterCredential(options: OpenRouterCredentialOptions): string {
  if (typeof options.path !== "string" || !options.path.trim() || !isAbsolute(options.path.trim())) {
    throw credentialError("openrouter_credential_path_invalid", "The OpenRouter credential path must be absolute");
  }
  const path = resolve(options.path.trim());
  const expectedServiceUid = serviceUid(options.serviceUid);
  try {
    const parent = lstatSync(dirname(path));
    if (parent.isSymbolicLink() || !parent.isDirectory()) {
      throw credentialError("openrouter_credential_parent_invalid", "The OpenRouter credential directory is not trusted");
    }
    if (!acceptedOwner(parent.uid, expectedServiceUid) || (parent.mode & 0o022) !== 0) {
      throw credentialError("openrouter_credential_parent_permissions", "The OpenRouter credential directory is not privately controlled");
    }

    const linkState = lstatSync(path);
    if (linkState.isSymbolicLink() || !linkState.isFile()) {
      throw credentialError("openrouter_credential_file_invalid", "The OpenRouter credential must be a regular non-symlink file");
    }

    const noFollow = "O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0;
    const descriptor = openSync(path, constants.O_RDONLY | noFollow);
    try {
      const state = fstatSync(descriptor);
      const mode = state.mode & 0o777;
      if (!state.isFile() || !acceptedOwner(state.uid, expectedServiceUid)) {
        throw credentialError("openrouter_credential_owner_invalid", "The OpenRouter credential owner is not trusted");
      }
      if (!ALLOWED_FILE_MODES.has(mode)) {
        throw credentialError("openrouter_credential_mode_invalid", "The OpenRouter credential file must use mode 0400 or 0600");
      }
      if (state.size < 1 || state.size > MAXIMUM_CREDENTIAL_BYTES) {
        throw credentialError("openrouter_credential_size_invalid", "The OpenRouter credential file size is invalid");
      }
      const value = readFileSync(descriptor, { encoding: "utf8" }).trim();
      if (value.length < 20 || value.length > 4_096 || /[\s\u0000-\u001F\u007F]/u.test(value)) {
        throw credentialError("openrouter_credential_content_invalid", "The OpenRouter credential content is invalid");
      }
      return value;
    } finally {
      closeSync(descriptor);
    }
  } catch (error) {
    if (error instanceof OpenRouterPlanningError) throw error;
    throw credentialError("openrouter_credential_unavailable", "The OpenRouter credential is unavailable");
  }
}

/**
 * Capture the startup credential result exactly once.
 *
 * Provider-connection writes atomically replace the canonical credential path.
 * Keeping the active process on this startup snapshot prevents a saved key
 * from silently hot-activating in an already running provider adapter. A
 * captured validation failure is also stable until restart, so repairing the
 * file cannot bypass the explicit activation boundary.
 */
export function captureOpenRouterCredential(
  options: OpenRouterCredentialOptions,
): OpenRouterCredentialReader {
  let value: string | undefined;
  let failure: unknown;
  try {
    value = readOpenRouterCredential(options);
  } catch (error) {
    failure = error;
  }
  return () => {
    if (failure !== undefined) throw failure;
    if (value === undefined) {
      throw credentialError(
        "openrouter_credential_unavailable",
        "The OpenRouter credential is unavailable",
      );
    }
    return value;
  };
}
