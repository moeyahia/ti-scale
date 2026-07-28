import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import {
  constants as fsConstants,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { canonicalJson } from "./canonical";
import type {
  ResearchDependencyAttestation,
  ResearchDependencyKind,
} from "./ResearchReadinessAttestation";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";

export const RESEARCH_READINESS_PROBE_SCHEMA_VERSION =
  "ti-scale.research-readiness-probe.v1" as const;
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,160}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const MAXIMUM_OUTPUT_BYTES = 16 * 1024;

export const RESEARCH_READINESS_EVALUATOR_SOURCE = String.raw`
import hashlib,json,os,resource,socket,sys
dependency,nonce=sys.argv[1],sys.argv[2]
path="/work/readiness-"+dependency
payload=("ti-scale:"+dependency+":"+nonce).encode()
fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
os.write(fd,payload);os.fsync(fd);os.close(fd)
write_read_verified=open(path,"rb").read()==payload
os.unlink(path)
network_denied=False
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(0.1)
try:
  network_denied=s.connect_ex(("127.0.0.1",9))!=0
finally:
  s.close()
outside_write_denied=False
try:
  open("/usr/ti-scale-readiness-write-test","wb").close()
except OSError:
  outside_write_denied=True
sensitive=("TOKEN","PASSWORD","SECRET","PRIVATE_KEY","API_KEY","COOKIE","CREDENTIAL")
credential_environment_empty=not any(any(mark in key.upper() for mark in sensitive) for key in os.environ)
limits={
 "addressSpace":resource.getrlimit(resource.RLIMIT_AS)[0],
 "cpuSeconds":resource.getrlimit(resource.RLIMIT_CPU)[0],
 "fileBytes":resource.getrlimit(resource.RLIMIT_FSIZE)[0],
 "openFiles":resource.getrlimit(resource.RLIMIT_NOFILE)[0],
 "processes":resource.getrlimit(resource.RLIMIT_NPROC)[0]
}
print(json.dumps({
 "schemaVersion":"ti-scale.research-readiness-result.v1",
 "dependency":dependency,
 "nonceHash":hashlib.sha256(nonce.encode()).hexdigest(),
 "writeReadVerified":write_read_verified,
 "resetVerified":os.listdir("/work")==[],
 "networkDenied":network_denied,
 "outsideWriteDenied":outside_write_denied,
 "credentialEnvironmentEmpty":credential_environment_empty,
 "limits":limits
},sort_keys=True,separators=(",",":")))
`;

export function researchReadinessEvaluatorSourceSha256(): string {
  return createHash("sha256")
    .update(RESEARCH_READINESS_EVALUATOR_SOURCE, "utf8")
    .digest("hex");
}

export interface ResearchReadinessProbeDescriptor {
  readonly schemaVersion: typeof RESEARCH_READINESS_PROBE_SCHEMA_VERSION;
  readonly descriptorVersion: string;
  readonly isolationExecutable: {
    readonly path: string;
    readonly sha256: string;
  };
  readonly resourceLimitExecutable: {
    readonly path: string;
    readonly sha256: string;
  };
  readonly evaluatorExecutable: {
    readonly path: string;
    readonly sha256: string;
  };
  readonly evaluatorId: string;
  readonly evaluatorSourceSha256: string;
  readonly timeoutMs: number;
  readonly receiptTtlMs: number;
  readonly limits: {
    readonly addressSpaceBytes: number;
    readonly cpuSeconds: number;
    readonly maxProcesses: number;
    readonly maxFileBytes: number;
    readonly maxOpenFiles: number;
  };
}

export interface ResearchReadinessProbeFailure {
  readonly dependency: ResearchDependencyKind;
  readonly code:
    | "isolation_unavailable"
    | "identity_mismatch"
    | "execution_timeout"
    | "execution_failed"
    | "isolation_failed"
    | "cleanup_failed";
  readonly explanation: string;
}

export interface LocalResearchReadinessProbeResult {
  readonly disposableLab: ResearchDependencyAttestation;
  readonly isolatedWorker: ResearchDependencyAttestation;
  readonly failures: readonly ResearchReadinessProbeFailure[];
  readonly workspaceCleanupVerified: boolean;
}

interface ExecutableIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly mode: number;
  readonly uid: number;
  readonly gid: number;
}

interface ProbeExecutionResult {
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly outputLimitExceeded: boolean;
  readonly spawnErrorCode?: string;
}

export interface ResearchReadinessProbeExecutor {
  execute(input: Readonly<{
    descriptor: ResearchReadinessProbeDescriptor;
    dependency: ResearchDependencyKind;
    nonce: string;
    workspacePath: string;
  }>): Promise<ProbeExecutionResult>;
}

interface EvaluatorOutput {
  readonly schemaVersion: "ti-scale.research-readiness-result.v1";
  readonly dependency: ResearchDependencyKind;
  readonly nonceHash: string;
  readonly writeReadVerified: boolean;
  readonly resetVerified: boolean;
  readonly networkDenied: boolean;
  readonly outsideWriteDenied: boolean;
  readonly credentialEnvironmentEmpty: boolean;
  readonly limits: {
    readonly addressSpace: number;
    readonly cpuSeconds: number;
    readonly fileBytes: number;
    readonly openFiles: number;
    readonly processes: number;
  };
}

type UnsignedResearchDependencyAttestation = Omit<
  ResearchDependencyAttestation,
  "receiptId" | "algorithm" | "signature"
>;

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (
    actual.length !== required.length
    || actual.some((key, index) => key !== required[index])
  ) throw new Error(`${label} has unexpected or missing fields`);
}

function absolutePath(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || !isAbsolute(value)
    || value.length > 4_096
    || CONTROL_CHARACTERS.test(value)
  ) throw new Error(`${label} must be an absolute safe path`);
  return resolve(value);
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256`);
  }
  return value;
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (
    !Number.isSafeInteger(value)
    || (value as number) < minimum
    || (value as number) > maximum
  ) throw new Error(`${label} must be between ${minimum} and ${maximum}`);
  return value as number;
}

function executableDescriptor(
  value: unknown,
  label: string,
): ResearchReadinessProbeDescriptor["isolationExecutable"] {
  if (!plainRecord(value)) throw new Error(`${label} must be an object`);
  exactKeys(value, ["path", "sha256"], label);
  return Object.freeze({
    path: absolutePath(value.path, `${label} path`),
    sha256: digest(value.sha256, `${label} identity`),
  });
}

export function parseResearchReadinessProbeDescriptor(
  input: unknown,
): ResearchReadinessProbeDescriptor {
  if (!plainRecord(input)) {
    throw new Error("Research readiness probe descriptor must be an object");
  }
  exactKeys(input, [
    "descriptorVersion",
    "evaluatorExecutable",
    "evaluatorId",
    "evaluatorSourceSha256",
    "isolationExecutable",
    "limits",
    "receiptTtlMs",
    "resourceLimitExecutable",
    "schemaVersion",
    "timeoutMs",
  ], "Research readiness probe descriptor");
  if (input.schemaVersion !== RESEARCH_READINESS_PROBE_SCHEMA_VERSION) {
    throw new Error("Research readiness probe descriptor schema is unsupported");
  }
  if (
    typeof input.descriptorVersion !== "string"
    || !SAFE_ID.test(input.descriptorVersion)
  ) throw new Error("Research readiness descriptor version is invalid");
  if (typeof input.evaluatorId !== "string" || !SAFE_ID.test(input.evaluatorId)) {
    throw new Error("Research readiness evaluator ID is invalid");
  }
  const evaluatorSourceSha256 = digest(
    input.evaluatorSourceSha256,
    "Research readiness evaluator source",
  );
  if (evaluatorSourceSha256 !== researchReadinessEvaluatorSourceSha256()) {
    throw new Error("Research readiness evaluator source identity changed");
  }
  if (!plainRecord(input.limits)) {
    throw new Error("Research readiness resource limits must be an object");
  }
  exactKeys(input.limits, [
    "addressSpaceBytes",
    "cpuSeconds",
    "maxFileBytes",
    "maxOpenFiles",
    "maxProcesses",
  ], "Research readiness resource limits");
  return Object.freeze({
    schemaVersion: RESEARCH_READINESS_PROBE_SCHEMA_VERSION,
    descriptorVersion: input.descriptorVersion,
    isolationExecutable: executableDescriptor(
      input.isolationExecutable,
      "Research readiness isolation executable",
    ),
    resourceLimitExecutable: executableDescriptor(
      input.resourceLimitExecutable,
      "Research readiness resource-limit executable",
    ),
    evaluatorExecutable: executableDescriptor(
      input.evaluatorExecutable,
      "Research readiness evaluator executable",
    ),
    evaluatorId: input.evaluatorId,
    evaluatorSourceSha256,
    timeoutMs: boundedInteger(input.timeoutMs, 250, 10_000, "Research readiness timeout"),
    receiptTtlMs: boundedInteger(
      input.receiptTtlMs,
      1_000,
      5 * 60_000,
      "Research readiness receipt TTL",
    ),
    limits: Object.freeze({
      addressSpaceBytes: boundedInteger(
        input.limits.addressSpaceBytes,
        64 * 1024 * 1024,
        512 * 1024 * 1024,
        "Research readiness address-space limit",
      ),
      cpuSeconds: boundedInteger(
        input.limits.cpuSeconds,
        1,
        5,
        "Research readiness CPU limit",
      ),
      maxProcesses: boundedInteger(
        input.limits.maxProcesses,
        1,
        32,
        "Research readiness process limit",
      ),
      maxFileBytes: boundedInteger(
        input.limits.maxFileBytes,
        4_096,
        4 * 1024 * 1024,
        "Research readiness file-size limit",
      ),
      maxOpenFiles: boundedInteger(
        input.limits.maxOpenFiles,
        16,
        128,
        "Research readiness open-file limit",
      ),
    }),
  });
}

export function loadTrustedResearchReadinessProbeDescriptor(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<ResearchReadinessProbeDescriptor> {
  return loadTrustedJson(
    { ...reference, maximumBytes: reference.maximumBytes ?? 32 * 1024 },
    parseResearchReadinessProbeDescriptor,
  );
}

export const RESEARCH_READINESS_CONFIGURATION_ENVIRONMENT = Object.freeze({
  trustRoot: "TI_SCALE_RESEARCH_READINESS_TRUST_ROOT",
  descriptorPath: "TI_SCALE_RESEARCH_READINESS_DESCRIPTOR_PATH",
  descriptorSha256: "TI_SCALE_RESEARCH_READINESS_DESCRIPTOR_SHA256",
  temporaryRoot: "TI_SCALE_RESEARCH_READINESS_TEMP_ROOT",
} as const);
export const RESEARCH_INTEGRITY_KEY_ENVIRONMENT = Object.freeze({
  inline: "TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY",
  file: "TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE",
} as const);

export type ProductionResearchReadinessProbeConfiguration =
  | Readonly<{
      status: "loaded";
      descriptor: ResearchReadinessProbeDescriptor;
      descriptorReceipt: LoadedTrustedJson<ResearchReadinessProbeDescriptor>["receipt"];
      temporaryRoot: string;
    }>
  | Readonly<{
      status: "unconfigured";
      reason: string;
    }>;

export function loadProductionResearchReadinessProbeConfiguration(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): ProductionResearchReadinessProbeConfiguration {
  const names = Object.values(RESEARCH_READINESS_CONFIGURATION_ENVIRONMENT);
  const values = Object.fromEntries(
    names.map((name) => [name, environment[name]?.trim() || undefined]),
  ) as Record<string, string | undefined>;
  const configured = names.filter((name) => values[name]).length;
  if (configured === 0) {
    return Object.freeze({
      status: "unconfigured",
      reason:
        "No complete trusted local Research readiness probe configuration is configured.",
    });
  }
  if (configured !== names.length) {
    const missing = names.filter((name) => !values[name]);
    throw new Error(
      `Research readiness configuration is incomplete; missing ${missing.join(", ")}`,
    );
  }
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const loaded = loadTrustedResearchReadinessProbeDescriptor({
    path: values[
      RESEARCH_READINESS_CONFIGURATION_ENVIRONMENT.descriptorPath
    ]!,
    trustRoot: values[
      RESEARCH_READINESS_CONFIGURATION_ENVIRONMENT.trustRoot
    ]!,
    expectedSha256: values[
      RESEARCH_READINESS_CONFIGURATION_ENVIRONMENT.descriptorSha256
    ]!,
    allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
  });
  return Object.freeze({
    status: "loaded",
    descriptor: loaded.value,
    descriptorReceipt: loaded.receipt,
    temporaryRoot: safeTemporaryRoot(values[
      RESEARCH_READINESS_CONFIGURATION_ENVIRONMENT.temporaryRoot
    ]!),
  });
}

export function resolveResearchIntegrityKey(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): string | undefined {
  const inline = environment[
    RESEARCH_INTEGRITY_KEY_ENVIRONMENT.inline
  ]?.trim();
  const explicitlyConfiguredFile = environment[
    RESEARCH_INTEGRITY_KEY_ENVIRONMENT.file
  ]?.trim();
  const credentialDirectory = environment.CREDENTIALS_DIRECTORY?.trim();
  const credentialFile = credentialDirectory
    && isAbsolute(credentialDirectory)
    ? join(credentialDirectory, "research-integrity-key")
    : undefined;
  const configuredFile = explicitlyConfiguredFile
    ?? (credentialFile && existsSync(credentialFile)
      ? credentialFile
      : undefined);
  if (inline && configuredFile) {
    throw new Error(
      "Configure one Research integrity key source, not both.",
    );
  }
  if (inline) {
    if (environment.NODE_ENV !== "test") {
      throw new Error(
        "Inline Research integrity keys are test-only; production requires a private key file.",
      );
    }
    if (Buffer.byteLength(inline) < 32 || Buffer.byteLength(inline) > 4_096) {
      throw new Error(
        "Research integrity key must contain 32 to 4096 bytes.",
      );
    }
    return inline;
  }
  if (!configuredFile) return undefined;
  const path = absolutePath(
    configuredFile,
    "Research integrity key file",
  );
  const metadata = lstatSync(path);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  if (
    metadata.isSymbolicLink()
    || !metadata.isFile()
    || (metadata.uid !== 0 && metadata.uid !== currentUid)
    || (metadata.mode & 0o077) !== 0
    || metadata.size < 32
    || metadata.size > 4_097
  ) {
    throw new Error(
      "Research integrity key file must be a private regular file owned by root or the service user.",
    );
  }
  const descriptor = openSync(
    path,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = statSync(`/proc/self/fd/${descriptor}`);
    if (
      opened.dev !== metadata.dev
      || opened.ino !== metadata.ino
      || opened.size !== metadata.size
      || opened.mtimeMs !== metadata.mtimeMs
      || opened.ctimeMs !== metadata.ctimeMs
    ) throw new Error("Research integrity key file identity changed");
    const value = readFileSync(descriptor, "utf8");
    if (
      value.includes("\n", 0)
      && !value.endsWith("\n")
      || value.trim().includes("\n")
    ) throw new Error("Research integrity key file must contain one line");
    const key = value.trim();
    if (Buffer.byteLength(key) < 32 || Buffer.byteLength(key) > 4_096) {
      throw new Error(
        "Research integrity key must contain 32 to 4096 bytes.",
      );
    }
    return key;
  } finally {
    closeSync(descriptor);
  }
}

function safeEqualHex(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

export class ResearchReadinessReceiptAuthority {
  readonly #key: Uint8Array;

  constructor(key: string | Uint8Array) {
    const bytes = typeof key === "string"
      ? Buffer.from(key, "utf8")
      : Buffer.from(key);
    if (bytes.byteLength < 32) {
      throw new Error(
        "Research readiness receipt key must contain at least 32 bytes.",
      );
    }
    this.#key = new Uint8Array(bytes);
  }

  private signature(payload: UnsignedResearchDependencyAttestation): string {
    return createHmac("sha256", this.#key)
      .update(canonicalJson(payload as never))
      .digest("hex");
  }

  createReceipt(
    payload: UnsignedResearchDependencyAttestation,
  ): ResearchDependencyAttestation {
    const signature = this.signature(payload);
    const receiptId = `research_readiness_${createHash("sha256")
      .update(`${canonicalJson(payload as never)}:${signature}`, "utf8")
      .digest("hex")
      .slice(0, 24)}`;
    return Object.freeze({
      ...structuredClone(payload),
      receiptId,
      algorithm: "hmac-sha256",
      signature,
    });
  }

  verifyReceipt(receipt: ResearchDependencyAttestation): boolean {
    const {
      receiptId,
      algorithm,
      signature,
      ...payload
    } = receipt;
    if (algorithm !== "hmac-sha256" || !SHA256.test(signature)) return false;
    const expectedSignature = this.signature(payload);
    const expectedId = `research_readiness_${createHash("sha256")
      .update(`${canonicalJson(payload as never)}:${expectedSignature}`, "utf8")
      .digest("hex")
      .slice(0, 24)}`;
    return receiptId === expectedId
      && safeEqualHex(signature, expectedSignature);
  }
}

function inspectExecutable(
  configured: ResearchReadinessProbeDescriptor["isolationExecutable"],
): ExecutableIdentity {
  let descriptor: number | undefined;
  try {
    const pathMetadata = lstatSync(configured.path);
    if (
      pathMetadata.isSymbolicLink()
      || !pathMetadata.isFile()
      || (pathMetadata.mode & 0o022) !== 0
      || (pathMetadata.mode & 0o7000) !== 0
      || (pathMetadata.mode & 0o111) === 0
    ) throw new Error("unsafe_executable");
    descriptor = openSync(
      configured.path,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const opened = statSync(`/proc/self/fd/${descriptor}`);
    if (
      opened.dev !== pathMetadata.dev
      || opened.ino !== pathMetadata.ino
      || opened.size !== pathMetadata.size
      || opened.mtimeMs !== pathMetadata.mtimeMs
      || opened.ctimeMs !== pathMetadata.ctimeMs
    ) throw new Error("executable_identity_changed");
    const sha256 = createHash("sha256")
      .update(readFileSync(descriptor))
      .digest("hex");
    if (sha256 !== configured.sha256) {
      throw new Error("executable_identity_mismatch");
    }
    return Object.freeze({
      path: configured.path,
      sha256,
      sizeBytes: opened.size,
      mode: opened.mode & 0o7777,
      uid: opened.uid,
      gid: opened.gid,
    });
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The descriptor is process-local and may already be closed.
      }
    }
  }
}

function killGroup(child: ChildProcess): void {
  if (child.pid && process.platform !== "win32") {
    try {
      process.kill(-child.pid, "SIGKILL");
      return;
    } catch {
      // Fall through to the tracked process.
    }
  }
  try { child.kill("SIGKILL"); } catch { /* already terminal */ }
}

function executeProbe(
  input: Parameters<ResearchReadinessProbeExecutor["execute"]>[0],
): Promise<ProbeExecutionResult> {
  const { descriptor, dependency, nonce, workspacePath } = input;
  const limits = descriptor.limits;
  const argumentsList = [
    "--unshare-all",
    "--unshare-net",
    "--die-with-parent",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--symlink", "usr/sbin", "/sbin",
    "--dir", "/etc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--bind", workspacePath, "/work",
    "--clearenv",
    "--setenv", "HOME", "/tmp",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "LC_ALL", "C.UTF-8",
    "--chdir", "/work",
    "--",
    descriptor.resourceLimitExecutable.path,
    `--as=${limits.addressSpaceBytes}`,
    `--cpu=${limits.cpuSeconds}`,
    `--nproc=${limits.maxProcesses}`,
    `--fsize=${limits.maxFileBytes}`,
    `--nofile=${limits.maxOpenFiles}`,
    "--",
    descriptor.evaluatorExecutable.path,
    "-I",
    "-S",
    "-c",
    RESEARCH_READINESS_EVALUATOR_SOURCE,
    dependency,
    nonce,
  ];
  return new Promise((resolveResult) => {
    const child = spawn(
      descriptor.isolationExecutable.path,
      argumentsList,
      {
        detached: true,
        shell: false,
        windowsHide: true,
        env: { HOME: "/nonexistent", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let timedOut = false;
    let outputLimitExceeded = false;
    let spawnErrorCode: string | undefined;
    const collect = (destination: Buffer[], chunk: Buffer): void => {
      bytes += chunk.length;
      if (bytes <= MAXIMUM_OUTPUT_BYTES) destination.push(chunk);
      else {
        outputLimitExceeded = true;
        killGroup(child);
      }
    };
    child.stdout!.on("data", (chunk: Buffer) => collect(stdout, chunk));
    child.stderr!.on("data", (chunk: Buffer) => collect(stderr, chunk));
    child.on("error", (error: NodeJS.ErrnoException) => {
      spawnErrorCode = error.code ?? "SPAWN_ERROR";
    });
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup(child);
    }, descriptor.timeoutMs);
    timer.unref?.();
    child.on("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolveResult({
        exitCode,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        timedOut,
        outputLimitExceeded,
        ...(spawnErrorCode ? { spawnErrorCode } : {}),
      });
    });
  });
}

function parseOutput(
  value: string,
  dependency: ResearchDependencyKind,
  nonce: string,
  descriptor: ResearchReadinessProbeDescriptor,
): EvaluatorOutput {
  const line = value.trim();
  if (!line || line.includes("\n") || Buffer.byteLength(line) > 8 * 1024) {
    throw new Error("evaluator_output_invalid");
  }
  const parsed = JSON.parse(line) as unknown;
  if (!plainRecord(parsed)) throw new Error("evaluator_output_invalid");
  exactKeys(parsed, [
    "credentialEnvironmentEmpty",
    "dependency",
    "limits",
    "networkDenied",
    "nonceHash",
    "outsideWriteDenied",
    "resetVerified",
    "schemaVersion",
    "writeReadVerified",
  ], "Research readiness evaluator output");
  if (!plainRecord(parsed.limits)) throw new Error("evaluator_limits_invalid");
  exactKeys(parsed.limits, [
    "addressSpace",
    "cpuSeconds",
    "fileBytes",
    "openFiles",
    "processes",
  ], "Research readiness evaluator limits");
  const expected = descriptor.limits;
  if (
    parsed.schemaVersion !== "ti-scale.research-readiness-result.v1"
    || parsed.dependency !== dependency
    || parsed.nonceHash !== createHash("sha256").update(nonce).digest("hex")
    || parsed.writeReadVerified !== true
    || parsed.resetVerified !== true
    || parsed.networkDenied !== true
    || parsed.outsideWriteDenied !== true
    || parsed.credentialEnvironmentEmpty !== true
    || parsed.limits.addressSpace !== expected.addressSpaceBytes
    || parsed.limits.cpuSeconds !== expected.cpuSeconds
    || parsed.limits.fileBytes !== expected.maxFileBytes
    || parsed.limits.openFiles !== expected.maxOpenFiles
    || parsed.limits.processes !== expected.maxProcesses
  ) throw new Error("evaluator_isolation_or_limits_failed");
  return parsed as unknown as EvaluatorOutput;
}

function safeTemporaryRoot(value: string): string {
  const root = resolve(value);
  if (
    !isAbsolute(root)
    || root === resolve(sep)
    || CONTROL_CHARACTERS.test(root)
  ) throw new Error("Research readiness temporary root is unsafe");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const metadata = statSync(root);
  if (
    !metadata.isDirectory()
    || (metadata.mode & 0o022) !== 0
    || (metadata.uid !== 0
      && metadata.uid !== (process.geteuid?.() ?? process.getuid?.() ?? 0))
  ) throw new Error("Research readiness temporary root is not private");
  return root;
}

export class LocalResearchReadinessProbe {
  readonly #executor: ResearchReadinessProbeExecutor;
  readonly #temporaryRoot: string;
  readonly #clock: () => Date;

  constructor(
    readonly descriptor: ResearchReadinessProbeDescriptor,
    readonly authority: ResearchReadinessReceiptAuthority,
    options: {
      readonly temporaryRoot?: string;
      readonly executor?: ResearchReadinessProbeExecutor;
      readonly clock?: () => Date;
    } = {},
  ) {
    this.descriptor = parseResearchReadinessProbeDescriptor(descriptor);
    this.#executor = options.executor ?? { execute: executeProbe };
    this.#temporaryRoot = safeTemporaryRoot(
      options.temporaryRoot ?? join(tmpdir(), "ti-scale-research-readiness"),
    );
    this.#clock = options.clock ?? (() => new Date());
  }

  private probeIdentity() {
    return Object.freeze({
      evaluatorId: this.descriptor.evaluatorId,
      evaluatorSha256: this.descriptor.evaluatorSourceSha256,
      isolationToolId: this.descriptor.descriptorVersion,
      isolationToolSha256: this.descriptor.isolationExecutable.sha256,
      resourceLimitToolSha256:
        this.descriptor.resourceLimitExecutable.sha256,
      evaluatorToolSha256: this.descriptor.evaluatorExecutable.sha256,
    });
  }

  private receipt(
    dependency: ResearchDependencyKind,
    input: {
      readonly status: "pass" | "fail";
      readonly evidenceHash: string;
      readonly failureCode?: string;
    },
  ): ResearchDependencyAttestation {
    const observedAt = this.#clock();
    return this.authority.createReceipt({
      schemaVersion: "2.4",
      dependency,
      attestorId: this.descriptor.evaluatorId,
      status: input.status,
      observedAt: observedAt.toISOString(),
      expiresAt: new Date(
        observedAt.getTime() + this.descriptor.receiptTtlMs,
      ).toISOString(),
      evidenceHash: input.evidenceHash,
      controls: {
        resetVerified:
          input.status === "pass" && dependency === "disposable_lab",
        liveClientTargetsAllowed: false,
        productionSecretsMounted: false,
        productionMutationAllowed: false,
        quotaBound: input.status === "pass",
      },
      probeIdentity: this.probeIdentity(),
      resourceLimits: structuredClone(this.descriptor.limits),
      failureCode: input.failureCode ?? null,
    });
  }

  private async runOne(
    dependency: ResearchDependencyKind,
  ): Promise<{
    readonly receipt: ResearchDependencyAttestation;
    readonly failure?: ResearchReadinessProbeFailure;
    readonly workspaceCleaned: boolean;
  }> {
    const nonce = randomBytes(24).toString("hex");
    const workspace = mkdtempSync(
      join(this.#temporaryRoot, `${dependency}-`),
    );
    let execution: ProbeExecutionResult | undefined;
    let output: EvaluatorOutput | undefined;
    let failure: ResearchReadinessProbeFailure | undefined;
    let cleanupVerified = false;
    try {
      inspectExecutable(this.descriptor.isolationExecutable);
      inspectExecutable(this.descriptor.resourceLimitExecutable);
      inspectExecutable(this.descriptor.evaluatorExecutable);
      execution = await this.#executor.execute({
        descriptor: this.descriptor,
        dependency,
        nonce,
        workspacePath: workspace,
      });
      if (execution.timedOut) {
        failure = {
          dependency,
          code: "execution_timeout",
          explanation: "The bounded target-free isolation probe timed out.",
        };
      } else if (
        execution.outputLimitExceeded
        || execution.spawnErrorCode
        || execution.exitCode !== 0
        || execution.signal !== null
        || execution.stderr.trim().length > 0
      ) {
        failure = {
          dependency,
          code: "execution_failed",
          explanation:
            "The target-free isolation worker did not complete cleanly.",
        };
      } else {
        try {
          output = parseOutput(
            execution.stdout,
            dependency,
            nonce,
            this.descriptor,
          );
        } catch {
          failure = {
            dependency,
            code: "isolation_failed",
            explanation:
              "The worker could not prove network, filesystem, credential, or resource isolation.",
          };
        }
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      failure = {
        dependency,
        code: code === "ENOENT"
          ? "isolation_unavailable"
          : String((error as Error).message).includes("identity")
            ? "identity_mismatch"
            : "isolation_unavailable",
        explanation: code === "ENOENT"
          ? "A hash-pinned local isolation dependency is missing."
          : "A hash-pinned local isolation dependency is unavailable or changed.",
      };
    } finally {
      try {
        rmSync(workspace, { recursive: true, force: true });
        cleanupVerified = !existsSync(workspace);
      } catch {
        cleanupVerified = false;
      }
    }
    if (!cleanupVerified) {
      failure = {
        dependency,
        code: "cleanup_failed",
        explanation:
          "The disposable probe workspace could not be removed completely.",
      };
    }
    const evidenceHash = createHash("sha256")
      .update(canonicalJson({
        dependency,
        descriptorVersion: this.descriptor.descriptorVersion,
        execution: execution
          ? {
              exitCode: execution.exitCode,
              signal: execution.signal,
              timedOut: execution.timedOut,
              outputLimitExceeded: execution.outputLimitExceeded,
              stdoutHash: createHash("sha256")
                .update(execution.stdout)
                .digest("hex"),
              stderrHash: createHash("sha256")
                .update(execution.stderr)
                .digest("hex"),
            }
          : null,
        output: output ?? null,
        cleanupVerified,
        failureCode: failure?.code ?? null,
      } as never))
      .digest("hex");
    return {
      receipt: this.receipt(dependency, {
        status: failure ? "fail" : "pass",
        evidenceHash,
        ...(failure ? { failureCode: failure.code } : {}),
      }),
      ...(failure ? { failure } : {}),
      workspaceCleaned: cleanupVerified,
    };
  }

  async run(): Promise<LocalResearchReadinessProbeResult> {
    const disposableLab = await this.runOne("disposable_lab");
    const isolatedWorker = await this.runOne("isolated_worker");
    return Object.freeze({
      disposableLab: disposableLab.receipt,
      isolatedWorker: isolatedWorker.receipt,
      failures: Object.freeze([
        ...(disposableLab.failure ? [disposableLab.failure] : []),
        ...(isolatedWorker.failure ? [isolatedWorker.failure] : []),
      ]),
      workspaceCleanupVerified:
        disposableLab.workspaceCleaned && isolatedWorker.workspaceCleaned,
    });
  }
}

export class ResearchReadinessProbeMonitor {
  readonly #refreshIntervalMs: number;
  private latestResult: LocalResearchReadinessProbeResult | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;
  private active: Promise<LocalResearchReadinessProbeResult> | undefined;
  private stopping = false;

  constructor(
    readonly probe: LocalResearchReadinessProbe,
    readonly authority: ResearchReadinessReceiptAuthority,
    options: {
      readonly refreshIntervalMs?: number;
    } = {},
  ) {
    this.#refreshIntervalMs = options.refreshIntervalMs
      ?? Math.max(1_000, Math.floor(probe.descriptor.receiptTtlMs / 2));
    if (
      !Number.isSafeInteger(this.#refreshIntervalMs)
      || this.#refreshIntervalMs < 1_000
      || this.#refreshIntervalMs >= probe.descriptor.receiptTtlMs
    ) {
      throw new Error(
        "Research readiness refresh must be at least one second and shorter than its receipt TTL.",
      );
    }
  }

  private refresh(): Promise<LocalResearchReadinessProbeResult> {
    if (this.active) return this.active;
    const active = this.probe.run().then((result) => {
      if (!this.stopping) this.latestResult = result;
      return result;
    }).finally(() => {
      if (this.active === active) this.active = undefined;
    });
    this.active = active;
    return active;
  }

  async start(): Promise<LocalResearchReadinessProbeResult> {
    if (this.stopping) throw new Error("Research readiness monitor is stopping");
    const result = await this.refresh();
    if (!this.timer) {
      this.timer = setInterval(() => {
        if (!this.stopping) void this.refresh().catch(() => undefined);
      }, this.#refreshIntervalMs);
      this.timer.unref?.();
    }
    return result;
  }

  read(
    dependency: ResearchDependencyKind,
  ): ResearchDependencyAttestation | undefined {
    if (this.stopping) return undefined;
    return dependency === "disposable_lab"
      ? this.latestResult?.disposableLab
      : this.latestResult?.isolatedWorker;
  }

  verify(attestation: ResearchDependencyAttestation): boolean {
    const current = this.read(attestation.dependency);
    return current?.receiptId === attestation.receiptId
      && this.authority.verifyReceipt(attestation);
  }

  beginStop(): void {
    if (this.stopping) return;
    this.stopping = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.latestResult = undefined;
  }

  async stop(): Promise<void> {
    this.beginStop();
    await this.active?.then(() => undefined, () => undefined);
  }
}
