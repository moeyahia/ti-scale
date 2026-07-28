import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  writeSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { writeDurableFileAtomically } from "./DurableAtomicFile";

export const RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA =
  "ti-scale.release-service-start-admission-installation.v1" as const;
export const RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME =
  ".release-start-admission-installation.json";

const DEFAULT_TRANSACTION_ROOT = "/var/lib/ti-scale/release-transactions";
const DEFAULT_HELPER_PATH = "/usr/local/libexec/ti-scale-release-start-admission.js";
const DEFAULT_WRAPPER_PATH = "/usr/local/libexec/ti-scale-service-wrapper.js";
const DEFAULT_DROP_IN_PATH =
  "/etc/systemd/system/ti-scale.service.d/10-release-start-admission.conf";
const HEX_SHA256 = /^[0-9a-f]{64}$/u;

export type ReleaseServiceStartAdmissionInstallationPhase =
  | "prepared"
  | "helper_written"
  | "drop_in_written"
  | "files_written"
  | "committed";

export type ReleaseServiceStartAdmissionInstallationBoundary =
  | "wrapper_guard_written"
  | "journal_prepared"
  | "helper_written"
  | "helper_recorded"
  | "drop_in_written"
  | "drop_in_recorded"
  | "files_written"
  | "activation_started"
  | "service_manager_reloaded"
  | "activation_verified"
  | "committed";

export type ReleaseServiceStartAdmissionInstalledArtifact =
  | "wrapper"
  | "helper"
  | "drop_in";

export type ReleaseServiceStartAdmissionInPlaceWritePhase =
  | "opened"
  | "partial_written"
  | "file_written"
  | "file_synced"
  | "directory_synced";

interface InstallationArtifact {
  readonly targetPath: string;
  readonly sha256: string;
  readonly mode: number;
}

interface InstallationJournalCore {
  readonly schemaVersion: typeof RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA;
  readonly installationId: string;
  readonly phase: ReleaseServiceStartAdmissionInstallationPhase;
  readonly wrapper: InstallationArtifact;
  readonly helper: InstallationArtifact;
  readonly dropIn: InstallationArtifact;
}

interface InstallationJournal extends InstallationJournalCore {
  readonly recordSha256: string;
}

export interface ReleaseServiceStartAdmissionInstallationPayload {
  readonly helperBytes: Uint8Array;
  readonly wrapperBytes: Uint8Array;
  readonly dropInBytes: Uint8Array;
}

export interface ReleaseServiceStartAdmissionAccessCommandInvocation {
  readonly purpose:
    | "enforce_traverse_only_acl"
    | "probe_traverse"
    | "probe_list"
    | "probe_read"
    | "probe_write";
  readonly allowNonZeroExit: boolean;
}

export interface ReleaseServiceStartAdmissionAccessCommandResult {
  readonly exitCode: number;
}

export type ReleaseServiceStartAdmissionAccessCommandRunner = (
  command: readonly string[],
  invocation: ReleaseServiceStartAdmissionAccessCommandInvocation,
) => ReleaseServiceStartAdmissionAccessCommandResult;

export interface ReleaseServiceStartAdmissionInstallationOptions {
  readonly transactionRoot?: string;
  readonly helperPath?: string;
  readonly wrapperPath?: string;
  readonly dropInPath?: string;
  readonly expectedUid?: number;
  readonly expectedGid?: number;
  readonly trustedAncestorBoundary?: string;
  readonly serviceUser?: string;
  readonly runServiceAccessCommand?: ReleaseServiceStartAdmissionAccessCommandRunner;
  readonly onBoundary?: (boundary: ReleaseServiceStartAdmissionInstallationBoundary) => void;
  readonly onInPlaceWritePhase?: (
    artifact: ReleaseServiceStartAdmissionInstalledArtifact,
    phase: ReleaseServiceStartAdmissionInPlaceWritePhase,
  ) => void;
}

export interface ReleaseServiceStartAdmissionInstallationResult {
  readonly schemaVersion: typeof RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA;
  readonly status: "installed" | "repaired_forward" | "already_installed";
  readonly installationId: string;
  readonly phase: "committed";
  readonly helperSha256: string;
  readonly wrapperSha256: string;
  readonly dropInSha256: string;
}

export interface ReleaseServiceStartAdmissionFilesWritten {
  readonly schemaVersion: typeof RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA;
  readonly status: "files_written" | "repaired_forward" | "already_installed";
  readonly installationId: string;
  readonly phase: "files_written" | "committed";
  readonly helperSha256: string;
  readonly wrapperSha256: string;
  readonly dropInSha256: string;
}

export interface ReleaseServiceStartAdmissionActivationControl {
  serviceManagerReloaded(): void;
}

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function expectedPaths(options: ReleaseServiceStartAdmissionInstallationOptions): {
  readonly helper: string;
  readonly wrapper: string;
  readonly dropIn: string;
} {
  return Object.freeze({
    helper: resolve(options.helperPath ?? DEFAULT_HELPER_PATH),
    wrapper: resolve(options.wrapperPath ?? DEFAULT_WRAPPER_PATH),
    dropIn: resolve(options.dropInPath ?? DEFAULT_DROP_IN_PATH),
  });
}

function transactionRoot(options: ReleaseServiceStartAdmissionInstallationOptions): string {
  return resolve(options.transactionRoot ?? DEFAULT_TRANSACTION_ROOT);
}

function journalPath(options: ReleaseServiceStartAdmissionInstallationOptions): string {
  return join(
    transactionRoot(options),
    RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME,
  );
}

function assertTrustedDirectory(path: string, expectedUid: number, expectedGid: number): void {
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() ||
    metadata.uid !== expectedUid || metadata.gid !== expectedGid ||
    (metadata.mode & 0o022) !== 0
  ) throw new Error(`Release-start installation journal directory is not trusted: ${path}`);
}

function assertTrustedAncestorChain(
  path: string,
  boundaryPath: string,
  expectedUid: number,
): void {
  const boundary = resolve(boundaryPath);
  let cursor = dirname(resolve(path));
  while (true) {
    const metadata = lstatSync(cursor);
    if (
      !metadata.isDirectory() || metadata.isSymbolicLink() ||
      metadata.uid !== expectedUid ||
      (metadata.mode & 0o022) !== 0
    ) {
      throw new Error(
        `Release-start installation journal ancestor is not trusted: ${cursor}`,
      );
    }
    if (cursor === boundary) return;
    if (cursor === "/") {
      throw new Error(
        `Release-start installation journal root is outside its trusted boundary: ${path}`,
      );
    }
    cursor = dirname(cursor);
  }
}

function assertTrustedOpenedDirectory(
  path: string,
  descriptor: number,
  expectedUid: number,
  expectedGid: number,
): void {
  const opened = fstatSync(descriptor);
  const named = lstatSync(path);
  if (
    !opened.isDirectory() ||
    !named.isDirectory() || named.isSymbolicLink() ||
    opened.dev !== named.dev || opened.ino !== named.ino ||
    opened.uid !== expectedUid || opened.gid !== expectedGid ||
    named.uid !== expectedUid || named.gid !== expectedGid ||
    (opened.mode & 0o022) !== 0 || (named.mode & 0o022) !== 0
  ) {
    throw new Error(
      `Release-start installation journal directory inode is not trusted: ${path}`,
    );
  }
}

function serviceAccessConfiguration(
  options: ReleaseServiceStartAdmissionInstallationOptions,
): {
  readonly serviceUser: string;
  readonly run: ReleaseServiceStartAdmissionAccessCommandRunner;
} | undefined {
  if (options.serviceUser === undefined && options.runServiceAccessCommand === undefined) {
    return undefined;
  }
  if (
    options.serviceUser === undefined ||
    options.runServiceAccessCommand === undefined
  ) {
    throw new Error(
      "Release-start service access requires both a service user and an access-command runner",
    );
  }
  const serviceUser = options.serviceUser.trim();
  if (!/^[a-z_][a-z0-9_-]{0,31}$/u.test(serviceUser)) {
    throw new Error("Release-start service user is malformed");
  }
  return Object.freeze({
    serviceUser,
    run: options.runServiceAccessCommand,
  });
}

function runServiceAccessCommand(
  access: NonNullable<ReturnType<typeof serviceAccessConfiguration>>,
  command: readonly string[],
  invocation: ReleaseServiceStartAdmissionAccessCommandInvocation,
): number {
  const result = access.run(Object.freeze([...command]), Object.freeze(invocation));
  if (
    !Number.isSafeInteger(result.exitCode) ||
    result.exitCode < 0 || result.exitCode > 255
  ) {
    throw new Error("Release-start service access command returned an invalid exit code");
  }
  if (!invocation.allowNonZeroExit && result.exitCode !== 0) {
    throw new Error(
      `Release-start service access command failed during ${invocation.purpose}`,
    );
  }
  return result.exitCode;
}

function serviceCanTraverse(
  path: string,
  access: NonNullable<ReturnType<typeof serviceAccessConfiguration>>,
): boolean {
  return runServiceAccessCommand(
    access,
    [
      "/usr/sbin/runuser",
      "--user",
      access.serviceUser,
      "--",
      "/usr/bin/test",
      "-x",
      path,
    ],
    { purpose: "probe_traverse", allowNonZeroExit: true },
  ) === 0;
}

function serviceCanAccessDirectory(
  path: string,
  access: NonNullable<ReturnType<typeof serviceAccessConfiguration>>,
  flag: "-r" | "-w",
): boolean {
  return runServiceAccessCommand(
    access,
    [
      "/usr/sbin/runuser",
      "--user",
      access.serviceUser,
      "--",
      "/usr/bin/test",
      flag,
      path,
    ],
    {
      purpose: flag === "-r" ? "probe_list" : "probe_write",
      allowNonZeroExit: true,
    },
  ) === 0;
}

/**
 * The stable wrapper runs as the unprivileged Ti-Scale account and verifies
 * the content-free committed installation journal before application exec.
 * Canonicalize the dedicated root to a named service-user ACL containing only
 * directory traversal. Exact cross-identity probes prove that the service can
 * traverse but cannot list or write the root before installation continues.
 */
export function prepareReleaseServiceStartAdmissionTransactionRoot(
  options: ReleaseServiceStartAdmissionInstallationOptions = {},
): void {
  const expectedUid = options.expectedUid ?? 0;
  const expectedGid = options.expectedGid ?? 0;
  const root = transactionRoot(options);
  if (!existsSync(root)) {
    throw new Error("Release-start installation journal root is missing");
  }
  assertTrustedAncestorChain(
    root,
    options.trustedAncestorBoundary ?? "/",
    expectedUid,
  );
  const closeOnExec =
    (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;
  const noFollow =
    (constants as unknown as Readonly<Record<string, number>>).O_NOFOLLOW ?? 0;
  const descriptor = openSync(
    root,
    constants.O_RDONLY | constants.O_DIRECTORY | closeOnExec | noFollow,
  );
  try {
    assertTrustedOpenedDirectory(root, descriptor, expectedUid, expectedGid);
    const originalSpecialMode = fstatSync(descriptor).mode & 0o7000;
    const access = serviceAccessConfiguration(options);
    if (access) {
      try {
        runServiceAccessCommand(
          access,
          [
            "/usr/bin/setfacl",
            "--remove-default",
            "--set",
            `user::rwx,user:${access.serviceUser}:--x,group::---,mask::--x,other::---`,
            "--",
            root,
          ],
          { purpose: "enforce_traverse_only_acl", allowNonZeroExit: false },
        );
        if (!serviceCanTraverse(root, access)) {
          throw new Error(
            "Release-start installation journal root remains inaccessible to the service user",
          );
        }
        if (
          serviceCanAccessDirectory(root, access, "-r") ||
          serviceCanAccessDirectory(root, access, "-w")
        ) {
          throw new Error(
            "Release-start installation journal root grants excessive service-user access",
          );
        }
      } finally {
        // The ACL operation can mutate directory metadata even when its command
        // or a subsequent proof fails. Flush the descriptor-bound directory
        // before propagating that failure.
        fsyncSync(descriptor);
      }
    }
    // Re-bind the name after the only external path operation, then durably
    // flush the same directory descriptor even on an already-correct retry.
    assertTrustedOpenedDirectory(root, descriptor, expectedUid, expectedGid);
    if ((fstatSync(descriptor).mode & 0o7000) !== originalSpecialMode) {
      throw new Error(
        "Release-start installation journal root special mode changed unexpectedly",
      );
    }
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function assertTrustedFile(
  path: string,
  mode: number,
  expectedUid: number,
  expectedGid: number,
): void {
  const metadata = lstatSync(path);
  if (
    !metadata.isFile() || metadata.isSymbolicLink() ||
    metadata.uid !== expectedUid || metadata.gid !== expectedGid ||
    (metadata.mode & 0o777) !== mode
  ) throw new Error(`Release-start installation file is not trusted: ${path}`);
}

function artifact(
  targetPath: string,
  bytes: Uint8Array,
  mode: number,
): InstallationArtifact {
  return Object.freeze({
    targetPath: resolve(targetPath),
    sha256: sha256(bytes),
    mode,
  });
}

function installationId(
  wrapper: InstallationArtifact,
  helper: InstallationArtifact,
  dropIn: InstallationArtifact,
): string {
  return sha256(canonicalJson({
    schemaVersion: RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA,
    wrapper,
    helper,
    dropIn,
  }));
}

function journalRecord(core: InstallationJournalCore): InstallationJournal {
  return Object.freeze({
    ...core,
    recordSha256: sha256(canonicalJson(core)),
  });
}

function parseArtifact(value: unknown): InstallationArtifact {
  if (!value || typeof value !== "object") {
    throw new Error("Release-start installation artifact record is malformed");
  }
  const artifact = value as Partial<InstallationArtifact>;
  if (
    typeof artifact.targetPath !== "string" ||
    typeof artifact.sha256 !== "string" || !HEX_SHA256.test(artifact.sha256) ||
    !Number.isSafeInteger(artifact.mode) ||
    (artifact.mode !== 0o755 && artifact.mode !== 0o644)
  ) throw new Error("Release-start installation artifact record is malformed");
  return artifact as InstallationArtifact;
}

function parseJournal(value: unknown): InstallationJournal {
  if (!value || typeof value !== "object") {
    throw new Error("Release-start installation journal is malformed");
  }
  const record = value as Partial<InstallationJournal>;
  if (
    record.schemaVersion !== RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA ||
    typeof record.installationId !== "string" || !HEX_SHA256.test(record.installationId) ||
    !["prepared", "helper_written", "drop_in_written", "files_written", "committed"]
      .includes(String(record.phase)) ||
    typeof record.recordSha256 !== "string" || !HEX_SHA256.test(record.recordSha256)
  ) throw new Error("Release-start installation journal is malformed");
  const wrapper = parseArtifact(record.wrapper);
  const helper = parseArtifact(record.helper);
  const dropIn = parseArtifact(record.dropIn);
  const core: InstallationJournalCore = {
    schemaVersion: RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA,
    installationId: record.installationId,
    phase: record.phase as ReleaseServiceStartAdmissionInstallationPhase,
    wrapper,
    helper,
    dropIn,
  };
  if (
    sha256(canonicalJson(core)) !== record.recordSha256 ||
    installationId(wrapper, helper, dropIn) !== record.installationId
  ) throw new Error("Release-start installation journal integrity check failed");
  return record as InstallationJournal;
}

function readJournal(
  options: ReleaseServiceStartAdmissionInstallationOptions,
  expectedUid: number,
  expectedGid: number,
): InstallationJournal | undefined {
  const path = journalPath(options);
  if (!existsSync(path)) return undefined;
  assertTrustedFile(path, 0o644, expectedUid, expectedGid);
  return parseJournal(JSON.parse(readFileSync(path, "utf8")));
}

function writeJournal(
  options: ReleaseServiceStartAdmissionInstallationOptions,
  core: InstallationJournalCore,
): InstallationJournal {
  const record = journalRecord(core);
  writeDurableFileAtomically(journalPath(options), canonicalJson(record), { mode: 0o644 });
  return record;
}

function journalMatchesTargets(
  journal: InstallationJournal,
  targets: ReturnType<typeof expectedPaths>,
): boolean {
  return resolve(journal.wrapper.targetPath) === targets.wrapper &&
    resolve(journal.helper.targetPath) === targets.helper &&
    resolve(journal.dropIn.targetPath) === targets.dropIn;
}

function targetMatches(
  artifact: InstallationArtifact,
  expectedUid: number,
  expectedGid: number,
): boolean {
  if (!existsSync(artifact.targetPath)) return false;
  try {
    assertTrustedFile(artifact.targetPath, artifact.mode, expectedUid, expectedGid);
    return sha256(readFileSync(artifact.targetPath)) === artifact.sha256;
  } catch {
    return false;
  }
}

function syncDirectory(path: string): void {
  const closeOnExec =
    (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | closeOnExec,
  );
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

/**
 * Writes only the fixed target inode/name. It creates no sibling containing
 * executable or configuration bytes. A process death may leave the fixed file
 * empty or partial; the wrapper-first gate makes that state closed and the
 * next invocation overwrites it forward.
 */
function writeTargetInPlace(
  label: ReleaseServiceStartAdmissionInstalledArtifact,
  artifact: InstallationArtifact,
  bytes: Uint8Array,
  options: ReleaseServiceStartAdmissionInstallationOptions,
  expectedUid: number,
  expectedGid: number,
): void {
  const parent = dirname(artifact.targetPath);
  if (!existsSync(parent)) {
    throw new Error(`Release-start installation target directory is missing: ${parent}`);
  }
  assertTrustedDirectory(parent, expectedUid, expectedGid);
  if (existsSync(artifact.targetPath)) {
    const current = lstatSync(artifact.targetPath);
    if (
      !current.isFile() || current.isSymbolicLink() ||
      current.uid !== expectedUid || current.gid !== expectedGid
    ) throw new Error(`Release-start installation target is not trusted: ${artifact.targetPath}`);
  }
  const closeOnExec =
    (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;
  const noFollow =
    (constants as unknown as Readonly<Record<string, number>>).O_NOFOLLOW ?? 0;
  const descriptor = openSync(
    artifact.targetPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC |
      closeOnExec | noFollow,
    artifact.mode,
  );
  let descriptorMetadata: ReturnType<typeof fstatSync>;
  try {
    options.onInPlaceWritePhase?.(label, "opened");
    fchmodSync(descriptor, artifact.mode);
    fchownSync(descriptor, expectedUid, expectedGid);
    const content = Buffer.from(bytes);
    const firstLength = content.byteLength === 0
      ? 0
      : Math.max(1, Math.floor(content.byteLength / 2));
    let offset = 0;
    while (offset < firstLength) {
      offset += writeSync(
        descriptor,
        content,
        offset,
        firstLength - offset,
      );
    }
    options.onInPlaceWritePhase?.(label, "partial_written");
    while (offset < content.byteLength) {
      offset += writeSync(
        descriptor,
        content,
        offset,
        content.byteLength - offset,
      );
    }
    options.onInPlaceWritePhase?.(label, "file_written");
    fsyncSync(descriptor);
    options.onInPlaceWritePhase?.(label, "file_synced");
    descriptorMetadata = fstatSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  const pathMetadata = lstatSync(artifact.targetPath);
  if (
    !descriptorMetadata.isFile() ||
    !pathMetadata.isFile() || pathMetadata.isSymbolicLink() ||
    descriptorMetadata.dev !== pathMetadata.dev ||
    descriptorMetadata.ino !== pathMetadata.ino ||
    pathMetadata.uid !== expectedUid || pathMetadata.gid !== expectedGid ||
    (pathMetadata.mode & 0o777) !== artifact.mode
  ) throw new Error(`Release-start installation target inode changed: ${artifact.targetPath}`);
  syncDirectory(parent);
  options.onInPlaceWritePhase?.(label, "directory_synced");
}

function result(
  status: ReleaseServiceStartAdmissionInstallationResult["status"],
  journal: InstallationJournal,
): ReleaseServiceStartAdmissionInstallationResult {
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA,
    status,
    installationId: journal.installationId,
    phase: "committed",
    helperSha256: journal.helper.sha256,
    wrapperSha256: journal.wrapper.sha256,
    dropInSha256: journal.dropIn.sha256,
  });
}

function preparedJournal(
  payload: ReleaseServiceStartAdmissionInstallationPayload,
  options: ReleaseServiceStartAdmissionInstallationOptions,
): InstallationJournalCore {
  const targets = expectedPaths(options);
  const wrapper = artifact(targets.wrapper, payload.wrapperBytes, 0o755);
  const helper = artifact(targets.helper, payload.helperBytes, 0o755);
  const dropIn = artifact(targets.dropIn, payload.dropInBytes, 0o644);
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA,
    installationId: installationId(wrapper, helper, dropIn),
    phase: "prepared",
    wrapper,
    helper,
    dropIn,
  });
}

function withPhase(
  record: InstallationJournal,
  phase: ReleaseServiceStartAdmissionInstallationPhase,
): InstallationJournalCore {
  return Object.freeze({
    schemaVersion: record.schemaVersion,
    installationId: record.installationId,
    phase,
    wrapper: record.wrapper,
    helper: record.helper,
    dropIn: record.dropIn,
  });
}

/**
 * Installs only to the fixed live paths. The journal contains paths, modes,
 * hashes, and phase metadata—never executable/configuration payload bytes.
 * The wrapper guard is written before the content-free journal. It denies
 * startup when that journal is missing, nonterminal, or bound to older bytes.
 * Every subsequent mixed state therefore remains closed.
 */
export function installReleaseServiceStartAdmissionFiles(
  payload: ReleaseServiceStartAdmissionInstallationPayload,
  options: ReleaseServiceStartAdmissionInstallationOptions = {},
): ReleaseServiceStartAdmissionFilesWritten {
  prepareReleaseServiceStartAdmissionTransactionRoot(options);
  const expectedUid = options.expectedUid ?? 0;
  const expectedGid = options.expectedGid ?? 0;
  const root = transactionRoot(options);
  if (!existsSync(root)) {
    throw new Error("Canonical release transaction root must exist before startup-gate installation");
  }
  assertTrustedDirectory(root, expectedUid, expectedGid);
  const targets = expectedPaths(options);
  const requested = preparedJournal(payload, options);
  const previous = readJournal(options, expectedUid, expectedGid);
  if (previous && !journalMatchesTargets(previous, targets)) {
    throw new Error("Release-start installation journal target binding is invalid");
  }
  if (
    previous?.phase === "committed" &&
    previous.installationId === requested.installationId &&
    [previous.wrapper, previous.helper, previous.dropIn]
      .every((item) => targetMatches(item, expectedUid, expectedGid))
  ) return Object.freeze({
    ...result("already_installed", previous),
    status: "already_installed" as const,
    phase: "committed" as const,
  });

  const repairing = previous !== undefined;
  // The first live write is itself the guard. If the process dies before the
  // journal write, this wrapper observes either a missing journal or the prior
  // committed hash and refuses application execution.
  writeTargetInPlace(
    "wrapper",
    requested.wrapper,
    payload.wrapperBytes,
    options,
    expectedUid,
    expectedGid,
  );
  options.onBoundary?.("wrapper_guard_written");
  let journal = writeJournal(options, requested);
  options.onBoundary?.("journal_prepared");

  writeTargetInPlace(
    "helper",
    journal.helper,
    payload.helperBytes,
    options,
    expectedUid,
    expectedGid,
  );
  options.onBoundary?.("helper_written");
  journal = writeJournal(options, withPhase(journal, "helper_written"));
  options.onBoundary?.("helper_recorded");

  writeTargetInPlace(
    "drop_in",
    journal.dropIn,
    payload.dropInBytes,
    options,
    expectedUid,
    expectedGid,
  );
  options.onBoundary?.("drop_in_written");
  journal = writeJournal(options, withPhase(journal, "drop_in_written"));
  options.onBoundary?.("drop_in_recorded");

  for (const item of [journal.wrapper, journal.helper, journal.dropIn]) {
    if (!targetMatches(item, expectedUid, expectedGid)) {
      throw new Error("Release-start installation could not verify an exact forward write");
    }
  }
  journal = writeJournal(options, withPhase(journal, "files_written"));
  options.onBoundary?.("files_written");
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_START_ADMISSION_INSTALLATION_SCHEMA,
    status: repairing ? "repaired_forward" as const : "files_written" as const,
    installationId: journal.installationId,
    phase: "files_written" as const,
    helperSha256: journal.helper.sha256,
    wrapperSha256: journal.wrapper.sha256,
    dropInSha256: journal.dropIn.sha256,
  });
}

export function commitReleaseServiceStartAdmissionInstallation(
  installationIdValue: string,
  options: ReleaseServiceStartAdmissionInstallationOptions = {},
): ReleaseServiceStartAdmissionInstallationResult {
  const expectedUid = options.expectedUid ?? 0;
  const expectedGid = options.expectedGid ?? 0;
  const installationId = installationIdValue.trim().toLowerCase();
  if (!HEX_SHA256.test(installationId)) {
    throw new Error("Release-start installation identity is malformed");
  }
  const root = transactionRoot(options);
  if (!existsSync(root)) {
    throw new Error("Release-start installation journal root is missing");
  }
  assertTrustedDirectory(root, expectedUid, expectedGid);
  const journal = readJournal(options, expectedUid, expectedGid);
  if (!journal || journal.installationId !== installationId) {
    throw new Error("Release-start installation journal identity changed before commit");
  }
  if (journal.phase === "committed") return result("already_installed", journal);
  if (journal.phase !== "files_written") {
    throw new Error("Release-start installation files are not durably complete");
  }
  if (!journalMatchesTargets(journal, expectedPaths(options))) {
    throw new Error("Release-start installation journal target binding is invalid");
  }
  for (const item of [journal.wrapper, journal.helper, journal.dropIn]) {
    if (!targetMatches(item, expectedUid, expectedGid)) {
      throw new Error("Release-start installation artifact changed before commit");
    }
  }
  const committed = writeJournal(options, withPhase(journal, "committed"));
  options.onBoundary?.("committed");
  return result("installed", committed);
}

export async function installReleaseServiceStartAdmissionWithActivation<T>(
  payload: ReleaseServiceStartAdmissionInstallationPayload,
  activateAndVerify: (
    control: ReleaseServiceStartAdmissionActivationControl,
  ) => T | Promise<T>,
  options: ReleaseServiceStartAdmissionInstallationOptions = {},
): Promise<{
  readonly installation: ReleaseServiceStartAdmissionInstallationResult;
  readonly activation: T;
}> {
  const files = installReleaseServiceStartAdmissionFiles(payload, options);
  options.onBoundary?.("activation_started");
  let reloaded = false;
  const activation = await activateAndVerify(Object.freeze({
    serviceManagerReloaded: () => {
      if (reloaded) {
        throw new Error("Release-start service-manager reload was reported more than once");
      }
      reloaded = true;
      options.onBoundary?.("service_manager_reloaded");
    },
  }));
  if (!reloaded) {
    throw new Error("Release-start activation did not prove a service-manager reload");
  }
  options.onBoundary?.("activation_verified");
  const installation = commitReleaseServiceStartAdmissionInstallation(
    files.installationId,
    options,
  );
  return Object.freeze({ installation, activation });
}

/**
 * Both installed entrypoints call this before admission or application exec.
 * Missing, malformed, nonterminal, or artifact-divergent state denies startup.
 */
export function assertReleaseServiceStartAdmissionInstallationCommitted(
  options: ReleaseServiceStartAdmissionInstallationOptions = {},
): ReleaseServiceStartAdmissionInstallationResult {
  const expectedUid = options.expectedUid ?? 0;
  const expectedGid = options.expectedGid ?? 0;
  const root = transactionRoot(options);
  if (!existsSync(root)) {
    throw new Error("Release-start installation journal root is missing");
  }
  assertTrustedDirectory(root, expectedUid, expectedGid);
  const journal = readJournal(options, expectedUid, expectedGid);
  if (!journal || journal.phase !== "committed") {
    throw new Error("Release-start installation is incomplete");
  }
  if (!journalMatchesTargets(journal, expectedPaths(options))) {
    throw new Error("Release-start installation journal target binding is invalid");
  }
  for (const item of [journal.wrapper, journal.helper, journal.dropIn]) {
    if (!targetMatches(item, expectedUid, expectedGid)) {
      throw new Error("Release-start installation artifact does not match committed state");
    }
  }
  return result("already_installed", journal);
}

/**
 * Prove that the exact final committed journal inode is readable by the
 * configured unprivileged service identity. This proof is intentionally
 * separate from the pre-commit activation probe because committing replaces
 * the journal atomically.
 */
export function assertReleaseServiceStartAdmissionJournalReadableByService(
  options: ReleaseServiceStartAdmissionInstallationOptions,
): ReleaseServiceStartAdmissionInstallationResult {
  const committed = assertReleaseServiceStartAdmissionInstallationCommitted(options);
  const access = serviceAccessConfiguration(options);
  if (!access) {
    throw new Error(
      "Release-start committed-journal access proof requires a service identity",
    );
  }
  const readable = runServiceAccessCommand(
    access,
    [
      "/usr/sbin/runuser",
      "--user",
      access.serviceUser,
      "--",
      "/usr/bin/test",
      "-r",
      journalPath(options),
    ],
    { purpose: "probe_read", allowNonZeroExit: true },
  ) === 0;
  if (!readable) {
    throw new Error(
      "Release-start committed installation journal is unreadable to the service user",
    );
  }
  return committed;
}
