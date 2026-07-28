import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { z } from "zod";
import { OpenRouterConnectionError } from "./OpenRouterConnectionError";
import {
  OPENROUTER_CONNECTION_SCHEMA_VERSION,
  type OpenRouterConnectionMutationResult,
  type PutOpenRouterConnectionInput,
  type StoredOpenRouterConnectionConfiguration,
} from "./OpenRouterConnectionTypes";
import { resolveOpenRouterModelConfiguration } from "./OpenRouterModelConfiguration";

export const DEFAULT_PROVIDER_CONFIGURATION_ROOT =
  "/var/lib/ti-scale/provider-config" as const;

const CONFIGURATION_FILE = "openrouter.json";
const CREDENTIAL_FILE = "openrouter.credential";
const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const MAXIMUM_CONFIGURATION_BYTES = 256 * 1024;
const MAXIMUM_IDEMPOTENCY_RECORDS = 64;
const SAFE_ID = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

const mutationReceiptSchema = z.object({
  keyHash: z.string().regex(SHA256),
  requestHash: z.string().regex(SHA256),
  version: z.number().int().positive(),
  createdAt: z.string().datetime(),
}).strict();

const configurationDocumentSchema = z.object({
  schemaVersion: z.literal(OPENROUTER_CONNECTION_SCHEMA_VERSION),
  providerId: z.literal("openrouter"),
  enabled: z.boolean(),
  model: z.string().min(1).max(240),
  credentialSha256: z.string().regex(SHA256).nullable(),
  version: z.number().int().positive(),
  updatedBy: z.string().regex(SAFE_ID),
  updatedAt: z.string().datetime(),
  mutationReceipts: z.array(mutationReceiptSchema).max(MAXIMUM_IDEMPOTENCY_RECORDS),
}).strict();

type ConfigurationDocument = z.infer<typeof configurationDocumentSchema>;

export interface OpenRouterConnectionStoreOptions {
  readonly root: string;
  readonly serviceUid?: number;
  readonly clock?: () => Date;
}

function digest(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function acceptedOwner(uid: number, serviceUid: number): boolean {
  return uid === 0 || uid === serviceUid;
}

function connectionError(
  code: string,
  message: string,
  status: number,
  category: ConstructorParameters<typeof OpenRouterConnectionError>[3],
  remediation: string,
): OpenRouterConnectionError {
  return new OpenRouterConnectionError(
    code,
    message,
    status,
    category,
    remediation,
  );
}

function persistenceError(code: string, message: string): OpenRouterConnectionError {
  return connectionError(
    code,
    message,
    503,
    "persistence",
    "Verify ownership and mode on the Ti-Scale provider-config directory, then retry.",
  );
}

function serviceUid(value: number | undefined): number {
  const result = value ?? (typeof process.geteuid === "function" ? process.geteuid() : -1);
  if (!Number.isSafeInteger(result) || result < 0) {
    throw persistenceError(
      "openrouter_connection_service_owner_unknown",
      "The Ti-Scale service owner could not be verified.",
    );
  }
  return result;
}

function assertSafeRoot(root: string): string {
  const normalized = root.trim();
  if (!normalized || !isAbsolute(normalized)) {
    throw persistenceError(
      "openrouter_connection_root_invalid",
      "The provider-configuration root must be an absolute path.",
    );
  }
  return resolve(normalized);
}

function assertPrivateDirectory(path: string, expectedUid: number): void {
  let state;
  try {
    state = lstatSync(path);
  } catch {
    throw persistenceError(
      "openrouter_connection_root_unavailable",
      "The provider-configuration root is unavailable.",
    );
  }
  if (
    !state.isDirectory()
    || state.isSymbolicLink()
    || !acceptedOwner(state.uid, expectedUid)
    || (state.mode & 0o077) !== 0
  ) {
    throw connectionError(
      "openrouter_connection_root_insecure",
      "The provider-configuration root is not a private service-owned directory.",
      503,
      "security_boundary",
      "Use a root- or service-owned mode-0700 directory without symbolic links.",
    );
  }
}

function assertPrivateFile(path: string, expectedUid: number): void {
  let state;
  try {
    state = lstatSync(path);
  } catch {
    throw persistenceError(
      "openrouter_connection_file_unavailable",
      "A provider-configuration file is unavailable.",
    );
  }
  if (
    !state.isFile()
    || state.isSymbolicLink()
    || !acceptedOwner(state.uid, expectedUid)
    || (state.mode & 0o777) !== FILE_MODE
  ) {
    throw connectionError(
      "openrouter_connection_file_insecure",
      "A provider-configuration file failed its private ownership or mode check.",
      503,
      "security_boundary",
      "Use regular root- or service-owned mode-0600 provider files without symbolic links.",
    );
  }
}

function safeActor(value: string): string {
  const actor = value.trim();
  if (!SAFE_ID.test(actor)) {
    throw connectionError(
      "openrouter_connection_actor_invalid",
      "The authenticated operator identity is invalid.",
      400,
      "invalid_input",
      "Sign in with a valid Ti-Scale operator identity.",
    );
  }
  return actor;
}

function safeIdempotencyKey(value: string): string {
  const key = value.trim();
  if (!IDEMPOTENCY_KEY.test(key)) {
    throw connectionError(
      "openrouter_connection_idempotency_key_invalid",
      "A valid Idempotency-Key header containing 8-200 safe characters is required.",
      400,
      "invalid_input",
      "Supply a unique Idempotency-Key and reuse it only for the same connection change.",
    );
  }
  return key;
}

function secretDigest(value: string): string {
  if (
    value.length < 20
    || value.length > 4_096
    || /[\s\u0000-\u001F\u007F]/u.test(value)
  ) {
    throw connectionError(
      "openrouter_connection_credential_invalid",
      "The OpenRouter credential does not meet the private credential format requirements.",
      400,
      "invalid_input",
      "Paste one OpenRouter completion key without whitespace.",
    );
  }
  return digest(value);
}

function requestDigest(input: PutOpenRouterConnectionInput): string {
  const credential = input.credential.action === "replace"
    ? { action: "replace", sha256: secretDigest(input.credential.value) }
    : input.credential;
  return digest(JSON.stringify({
    enabled: input.enabled,
    model: input.model,
    credential,
    expectedVersion: input.expectedVersion,
  }));
}

function publicConfiguration(
  document: ConfigurationDocument,
): StoredOpenRouterConnectionConfiguration {
  return {
    schemaVersion: document.schemaVersion,
    providerId: document.providerId,
    enabled: document.enabled,
    model: document.model,
    credentialSha256: document.credentialSha256,
    version: document.version,
    updatedBy: document.updatedBy,
    updatedAt: document.updatedAt,
  };
}

/**
 * Canonical OpenRouter connection storage.
 *
 * Writes are same-directory atomic replacements with no retained prior copy.
 * A crash between credential and metadata replacement is detected by the
 * stored credential hash and fails closed on the next read.
 */
export class OpenRouterConnectionStore {
  readonly root: string;
  readonly configurationPath: string;
  readonly credentialPath: string;
  readonly #uid: number;
  readonly #clock: () => Date;

  constructor(options: OpenRouterConnectionStoreOptions) {
    this.root = assertSafeRoot(options.root);
    this.configurationPath = join(this.root, CONFIGURATION_FILE);
    this.credentialPath = join(this.root, CREDENTIAL_FILE);
    this.#uid = serviceUid(options.serviceUid);
    this.#clock = options.clock ?? (() => new Date());
  }

  exists(): boolean {
    return existsSync(this.configurationPath);
  }

  read(): StoredOpenRouterConnectionConfiguration | null {
    const document = this.#readDocument();
    if (!document) return null;
    this.#assertCredentialState(document);
    return publicConfiguration(document);
  }

  put(
    input: PutOpenRouterConnectionInput,
    actorId: string,
    idempotencyKey: string,
  ): OpenRouterConnectionMutationResult {
    const actor = safeActor(actorId);
    const key = safeIdempotencyKey(idempotencyKey);
    resolveOpenRouterModelConfiguration({ model: input.model });
    if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 0) {
      throw connectionError(
        "openrouter_connection_expected_version_invalid",
        "expectedVersion must be a non-negative whole number.",
        400,
        "invalid_input",
        "Refresh the connection record and submit its exact version.",
      );
    }
    if (input.enabled && input.credential.action === "remove") {
      throw connectionError(
        "openrouter_connection_enabled_without_credential",
        "An enabled OpenRouter connection cannot remove its credential.",
        400,
        "invalid_input",
        "Choose Keep existing credential or Replace credential.",
      );
    }
    if (!input.enabled && input.credential.action !== "remove") {
      throw connectionError(
        "openrouter_connection_disabled_credential_action_invalid",
        "Disabling OpenRouter must remove the service-owned credential.",
        400,
        "invalid_input",
        "Choose Remove credential when disabling the connection.",
      );
    }

    const current = this.#readDocument();
    if (current) this.#assertCredentialState(current);
    const version = current?.version ?? 0;
    const keyHash = digest(key);
    const mutationHash = requestDigest(input);
    const replay = current?.mutationReceipts.find((item) => item.keyHash === keyHash);
    if (replay) {
      if (replay.requestHash !== mutationHash) {
        throw connectionError(
          "openrouter_connection_idempotency_conflict",
          "The Idempotency-Key was already used for a different connection change.",
          409,
          "state_conflict",
          "Use a new Idempotency-Key for the changed request.",
        );
      }
      return {
        configuration: publicConfiguration(current!),
        replayed: true,
      };
    }
    if (input.expectedVersion !== version) {
      throw connectionError(
        "openrouter_connection_version_conflict",
        `The OpenRouter connection changed from expected version ${input.expectedVersion} to ${version}.`,
        409,
        "state_conflict",
        "Refresh the connection record, review the current state, and submit again.",
      );
    }

    let nextCredentialHash: string | null;
    if (input.credential.action === "replace") {
      nextCredentialHash = secretDigest(input.credential.value);
      this.#ensureRoot();
      this.#atomicWrite(this.credentialPath, `${input.credential.value}\n`);
    } else if (input.credential.action === "keep") {
      if (!current?.credentialSha256 || !existsSync(this.credentialPath)) {
        throw connectionError(
          "openrouter_connection_credential_missing",
          "No existing service-owned OpenRouter credential can be kept.",
          409,
          "state_conflict",
          "Paste a credential and choose Replace credential.",
        );
      }
      nextCredentialHash = current.credentialSha256;
    } else {
      nextCredentialHash = null;
      this.#removeCredential();
    }

    const updatedAt = this.#clock().toISOString();
    const nextVersion = version + 1;
    const mutationReceipts = [
      ...(current?.mutationReceipts ?? []),
      {
        keyHash,
        requestHash: mutationHash,
        version: nextVersion,
        createdAt: updatedAt,
      },
    ].slice(-MAXIMUM_IDEMPOTENCY_RECORDS);
    const next: ConfigurationDocument = {
      schemaVersion: OPENROUTER_CONNECTION_SCHEMA_VERSION,
      providerId: "openrouter",
      enabled: input.enabled,
      model: input.model.trim(),
      credentialSha256: nextCredentialHash,
      version: nextVersion,
      updatedBy: actor,
      updatedAt,
      mutationReceipts,
    };
    this.#ensureRoot();
    this.#atomicWrite(this.configurationPath, `${JSON.stringify(next)}\n`);
    this.#assertCredentialState(next);
    return {
      configuration: publicConfiguration(next),
      replayed: false,
    };
  }

  #readDocument(): ConfigurationDocument | null {
    if (!existsSync(this.configurationPath)) return null;
    assertPrivateDirectory(this.root, this.#uid);
    assertPrivateFile(this.configurationPath, this.#uid);
    let bytes: Buffer;
    try {
      const descriptor = openSync(
        this.configurationPath,
        constants.O_RDONLY | ("O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0),
      );
      try {
        const state = fstatSync(descriptor);
        if (state.size < 1 || state.size > MAXIMUM_CONFIGURATION_BYTES) {
          throw persistenceError(
            "openrouter_connection_document_size_invalid",
            "The OpenRouter connection document size is invalid.",
          );
        }
        bytes = readFileSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
    } catch (error) {
      if (error instanceof OpenRouterConnectionError) throw error;
      throw persistenceError(
        "openrouter_connection_document_unavailable",
        "The OpenRouter connection document could not be read.",
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes.toString("utf8")) as unknown;
    } catch {
      throw persistenceError(
        "openrouter_connection_document_invalid",
        "The OpenRouter connection document is malformed.",
      );
    }
    const result = configurationDocumentSchema.safeParse(parsed);
    if (!result.success) {
      throw persistenceError(
        "openrouter_connection_document_invalid",
        "The OpenRouter connection document failed schema validation.",
      );
    }
    resolveOpenRouterModelConfiguration({ model: result.data.model });
    return result.data;
  }

  #assertCredentialState(document: ConfigurationDocument): void {
    if (!document.enabled) {
      if (document.credentialSha256 !== null) {
        throw persistenceError(
          "openrouter_connection_disabled_credential_metadata",
          "The disabled OpenRouter connection retains inconsistent credential metadata.",
        );
      }
      return;
    }
    if (!document.credentialSha256 || !existsSync(this.credentialPath)) {
      throw persistenceError(
        "openrouter_connection_credential_missing",
        "The enabled OpenRouter connection has no service-owned credential.",
      );
    }
    assertPrivateFile(this.credentialPath, this.#uid);
    let credential: Buffer;
    try {
      credential = readFileSync(this.credentialPath);
    } catch {
      throw persistenceError(
        "openrouter_connection_credential_unavailable",
        "The OpenRouter credential could not be verified.",
      );
    }
    if (digest(Buffer.from(credential.toString("utf8").trim(), "utf8")) !== document.credentialSha256) {
      throw persistenceError(
        "openrouter_connection_credential_integrity_mismatch",
        "The OpenRouter credential does not match its canonical configuration record.",
      );
    }
  }

  #ensureRoot(): void {
    try {
      mkdirSync(this.root, { recursive: true, mode: DIRECTORY_MODE });
      chmodSync(this.root, DIRECTORY_MODE);
    } catch {
      throw persistenceError(
        "openrouter_connection_root_create_failed",
        "The provider-configuration root could not be prepared.",
      );
    }
    assertPrivateDirectory(this.root, this.#uid);
  }

  #atomicWrite(path: string, value: string): void {
    this.#ensureRoot();
    const temporary = join(
      dirname(path),
      `.ti-scale-provider-write-${process.pid}-${randomUUID()}`,
    );
    let descriptor: number | undefined;
    try {
      descriptor = openSync(
        temporary,
        constants.O_CREAT
          | constants.O_EXCL
          | constants.O_WRONLY
          | ("O_NOFOLLOW" in constants ? constants.O_NOFOLLOW : 0),
        FILE_MODE,
      );
      writeFileSync(descriptor, value, { encoding: "utf8" });
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      chmodSync(temporary, FILE_MODE);
      renameSync(temporary, path);
      const directory = openSync(this.root, constants.O_RDONLY);
      try {
        fsyncSync(directory);
      } finally {
        closeSync(directory);
      }
      assertPrivateFile(path, this.#uid);
    } catch (error) {
      if (descriptor !== undefined) {
        try { closeSync(descriptor); } catch { /* best-effort descriptor close */ }
      }
      try {
        if (existsSync(temporary)) unlinkSync(temporary);
      } catch {
        // The original redacted persistence failure remains authoritative.
      }
      if (error instanceof OpenRouterConnectionError) throw error;
      throw persistenceError(
        "openrouter_connection_atomic_write_failed",
        "The provider configuration could not be committed atomically.",
      );
    }
  }

  #removeCredential(): void {
    if (!existsSync(this.credentialPath)) return;
    assertPrivateDirectory(this.root, this.#uid);
    assertPrivateFile(this.credentialPath, this.#uid);
    try {
      unlinkSync(this.credentialPath);
    } catch {
      throw persistenceError(
        "openrouter_connection_credential_remove_failed",
        "The service-owned OpenRouter credential could not be removed.",
      );
    }
  }
}

export function resolveProviderConfigurationRoot(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): string {
  return assertSafeRoot(
    environment.TI_SCALE_PROVIDER_CONFIG_ROOT?.trim()
      || DEFAULT_PROVIDER_CONFIGURATION_ROOT,
  );
}
