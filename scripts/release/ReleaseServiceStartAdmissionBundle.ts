import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  RELEASE_SERVICE_START_HELPER_PROTOCOL,
  releaseServiceStartAdmissionSelfReport,
} from "./service-start-admission";
import {
  RELEASE_SERVICE_WRAPPER_PROTOCOL,
  releaseServiceWrapperSelfReport,
} from "./service-wrapper";

export const RELEASE_SERVICE_START_ADMISSION_HELPER_PATH =
  "/usr/local/libexec/ti-scale-release-start-admission.js";
export const RELEASE_SERVICE_WRAPPER_PATH =
  "/usr/local/libexec/ti-scale-service-wrapper.js";
export const RELEASE_SERVICE_START_ADMISSION_DROP_IN_PATH =
  "/etc/systemd/system/ti-scale.service.d/10-release-start-admission.conf";
export const RELEASE_SERVICE_START_ADMISSION_BUN_PATH = "/usr/local/bin/bun";
export const RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND =
  `${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} run ${RELEASE_SERVICE_START_ADMISSION_HELPER_PATH}`;
export const RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND =
  `${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} run ${RELEASE_SERVICE_WRAPPER_PATH}`;
export const RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT =
  "/var/lib/ti-scale/release-transactions";
export const RELEASE_SERVICE_WRAPPER_USER = "ti-scale";
export const RELEASE_SERVICE_WRAPPER_GROUP = "ti-scale";
export const RELEASE_SERVICE_WRAPPER_WORKING_DIRECTORY = "/opt/ti-scale";

export interface ReleaseServiceStartAdmissionBundle {
  readonly schemaVersion: typeof RELEASE_SERVICE_START_HELPER_PROTOCOL;
  readonly bytes: Uint8Array;
  readonly sha256: string;
}

export interface ReleaseServiceWrapperBundle {
  readonly schemaVersion: typeof RELEASE_SERVICE_WRAPPER_PROTOCOL;
  readonly bytes: Uint8Array;
  readonly sha256: string;
}

export interface InstalledReleaseServiceStartAdmissionAttestation {
  readonly schemaVersion: "ti-scale.release-service-start-admission-installation.v2";
  readonly helperSha256: string;
  readonly wrapperSha256: string;
  readonly dropInSha256: string;
}

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function buildFailure(result: { readonly logs: readonly { readonly message: string }[] }): string {
  return result.logs.map((entry) => entry.message).join("; ") || "unknown Bun build failure";
}

export async function buildReleaseServiceStartAdmissionBundle(
  sourceRoot = resolve(import.meta.dir, "../.."),
): Promise<ReleaseServiceStartAdmissionBundle> {
  const entrypoint = join(resolve(sourceRoot), "scripts/release/service-start-admission.ts");
  const result = await Bun.build({
    entrypoints: [entrypoint],
    target: "bun",
    format: "esm",
    minify: false,
    sourcemap: "none",
    splitting: false,
  });
  if (!result.success) {
    throw new Error(`Could not build the stable release-start helper: ${buildFailure(result)}`);
  }
  const outputs = result.outputs.filter((output) => output.kind === "entry-point");
  if (outputs.length !== 1) {
    throw new Error("Release-start helper build did not produce exactly one self-contained entry point");
  }
  const bytes = new Uint8Array(await outputs[0]!.arrayBuffer());
  if (!bytes.byteLength) throw new Error("Release-start helper build produced an empty artifact");
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_START_HELPER_PROTOCOL,
    bytes,
    sha256: sha256(bytes),
  });
}

export async function buildReleaseServiceWrapperBundle(
  sourceRoot = resolve(import.meta.dir, "../.."),
): Promise<ReleaseServiceWrapperBundle> {
  const entrypoint = join(resolve(sourceRoot), "scripts/release/service-wrapper.ts");
  const result = await Bun.build({
    entrypoints: [entrypoint],
    target: "bun",
    format: "esm",
    minify: false,
    sourcemap: "none",
    splitting: false,
  });
  if (!result.success) {
    throw new Error(`Could not build the stable service wrapper: ${buildFailure(result)}`);
  }
  const outputs = result.outputs.filter((output) => output.kind === "entry-point");
  if (outputs.length !== 1) {
    throw new Error("Service wrapper build did not produce exactly one self-contained entry point");
  }
  const bytes = new Uint8Array(await outputs[0]!.arrayBuffer());
  if (!bytes.byteLength) throw new Error("Service wrapper build produced an empty artifact");
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_WRAPPER_PROTOCOL,
    bytes,
    sha256: sha256(bytes),
  });
}

function assertRootOwnedPath(
  path: string,
  kind: "file" | "directory",
  exactMode?: number,
  expectedUid = 0,
  expectedGid = 0,
): void {
  const metadata = lstatSync(path);
  const validKind = kind === "file" ? metadata.isFile() : metadata.isDirectory();
  if (
    !validKind || metadata.isSymbolicLink() ||
    metadata.uid !== expectedUid || metadata.gid !== expectedGid
  ) {
    throw new Error(`Release-start ${kind} is not a root-owned real ${kind}: ${path}`);
  }
  const mode = metadata.mode & 0o777;
  if (exactMode !== undefined ? mode !== exactMode : (mode & 0o022) !== 0) {
    throw new Error(`Release-start ${kind} has an unsafe mode: ${path}`);
  }
}

function assertRootOwnedAncestorChain(
  path: string,
  trustedBoundary = "/",
  expectedUid = 0,
  expectedGid = 0,
): void {
  const boundary = resolve(trustedBoundary);
  let cursor = dirname(resolve(path));
  while (true) {
    assertRootOwnedPath(cursor, "directory", undefined, expectedUid, expectedGid);
    if (cursor === boundary) return;
    if (cursor === "/") {
      throw new Error(`Release-start path is outside its trusted ancestor boundary: ${path}`);
    }
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error(`Release-start path has no trusted root ancestor: ${path}`);
    cursor = parent;
  }
}

function singleSystemdCommandBlock(rawValue: string): string | undefined {
  const blocks = rawValue.replace(/\s+/gu, " ").trim().match(/\{[^{}]*\}/gu) ?? [];
  return blocks.length === 1 ? blocks[0] : undefined;
}

function systemdField(block: string, field: string): string | undefined {
  const escaped = field.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return block.match(new RegExp(`(?:^|[;{]\\s*)${escaped}=([^;}]*)`, "u"))?.[1]?.trim();
}

export function serviceStartAdmissionConfigured(
  execStartPre: string,
  execStartPreEx: string,
): boolean {
  const legacy = singleSystemdCommandBlock(execStartPre);
  const extended = singleSystemdCommandBlock(execStartPreEx);
  if (!legacy || !extended) return false;
  const legacyExact = systemdField(legacy, "path") === RELEASE_SERVICE_START_ADMISSION_BUN_PATH &&
    systemdField(legacy, "argv[]") === RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND &&
    systemdField(legacy, "ignore_errors") === "no";
  const extendedExact = systemdField(extended, "path") === RELEASE_SERVICE_START_ADMISSION_BUN_PATH &&
    systemdField(extended, "argv[]") === RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND &&
    systemdField(extended, "flags") === "privileged";
  return legacyExact && extendedExact;
}

export function serviceWrapperConfigured(
  execStart: string,
  execStartEx: string,
): boolean {
  const legacy = singleSystemdCommandBlock(execStart);
  const extended = singleSystemdCommandBlock(execStartEx);
  if (!legacy || !extended) return false;
  const legacyExact = systemdField(legacy, "path") === RELEASE_SERVICE_START_ADMISSION_BUN_PATH &&
    systemdField(legacy, "argv[]") === RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND &&
    systemdField(legacy, "ignore_errors") === "no";
  const flags = systemdField(extended, "flags");
  const extendedExact = systemdField(extended, "path") === RELEASE_SERVICE_START_ADMISSION_BUN_PATH &&
    systemdField(extended, "argv[]") === RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND &&
    (flags === "" || flags === "none");
  return legacyExact && extendedExact;
}

export function serviceWrapperIdentityConfigured(
  user: string,
  group: string,
  workingDirectory: string,
  dynamicUser: string,
): boolean {
  return user.trim() === RELEASE_SERVICE_WRAPPER_USER &&
    group.trim() === RELEASE_SERVICE_WRAPPER_GROUP &&
    resolve(workingDirectory.trim()) === RELEASE_SERVICE_WRAPPER_WORKING_DIRECTORY &&
    dynamicUser.trim().toLowerCase() === "no";
}

export function serviceStartAdmissionMountConfigured(requiresMountsFor: string): boolean {
  return requiresMountsFor.split(/\s+/u).filter(Boolean)
    .includes(RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT);
}

export function releaseServiceStartAdmissionSelfReportMatches(rawValue: string): boolean {
  try {
    const actual = JSON.parse(rawValue) as Record<string, unknown>;
    const expected = releaseServiceStartAdmissionSelfReport();
    return actual.schemaVersion === expected.schemaVersion &&
      actual.authorizationSchema === expected.authorizationSchema &&
      Object.keys(actual).sort().join(",") === "authorizationSchema,schemaVersion";
  } catch {
    return false;
  }
}

export function releaseServiceWrapperSelfReportMatches(rawValue: string): boolean {
  try {
    const actual = JSON.parse(rawValue) as Record<string, unknown>;
    const expected = releaseServiceWrapperSelfReport();
    return actual.schemaVersion === expected.schemaVersion &&
      actual.guardedHealthSchema === expected.guardedHealthSchema &&
      actual.applicationEntrypoint === expected.applicationEntrypoint &&
      actual.applicationExecMode === expected.applicationExecMode &&
      Object.keys(actual).sort().join(",") ===
        "applicationEntrypoint,applicationExecMode,guardedHealthSchema,schemaVersion";
  } catch {
    return false;
  }
}

function nearestExistingDirectory(path: string): string {
  let cursor = dirname(resolve(path));
  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error(`Release-start target has no existing trusted ancestor: ${path}`);
    cursor = parent;
  }
  return cursor;
}

/** Pre-write guard: reject symlinked or non-root-writable target ancestors. */
export function assertReleaseServiceStartAdmissionInstallationTargets(options: {
  readonly helperPath?: string;
  readonly wrapperPath?: string;
  readonly dropInPath?: string;
  readonly bunPath?: string;
} = {}): void {
  const helperPath = resolve(options.helperPath ?? RELEASE_SERVICE_START_ADMISSION_HELPER_PATH);
  const wrapperPath = resolve(options.wrapperPath ?? RELEASE_SERVICE_WRAPPER_PATH);
  const dropInPath = resolve(options.dropInPath ?? RELEASE_SERVICE_START_ADMISSION_DROP_IN_PATH);
  const bunPath = resolve(options.bunPath ?? RELEASE_SERVICE_START_ADMISSION_BUN_PATH);
  assertRootOwnedAncestorChain(join(nearestExistingDirectory(helperPath), "pending"));
  assertRootOwnedAncestorChain(join(nearestExistingDirectory(wrapperPath), "pending"));
  assertRootOwnedAncestorChain(join(nearestExistingDirectory(dropInPath), "pending"));
  assertRootOwnedAncestorChain(bunPath);
  assertRootOwnedPath(bunPath, "file", 0o755);
}

export async function attestInstalledReleaseServiceStartAdmission(options: {
  readonly sourceRoot?: string;
  readonly helperPath?: string;
  readonly wrapperPath?: string;
  readonly dropInPath?: string;
  readonly bunPath?: string;
  readonly trustedAncestorBoundary?: string;
  readonly expectedUid?: number;
  readonly expectedGid?: number;
} = {}): Promise<InstalledReleaseServiceStartAdmissionAttestation> {
  const sourceRoot = resolve(options.sourceRoot ?? resolve(import.meta.dir, "../.."));
  const helperPath = resolve(options.helperPath ?? RELEASE_SERVICE_START_ADMISSION_HELPER_PATH);
  const wrapperPath = resolve(options.wrapperPath ?? RELEASE_SERVICE_WRAPPER_PATH);
  const dropInPath = resolve(options.dropInPath ?? RELEASE_SERVICE_START_ADMISSION_DROP_IN_PATH);
  const bunPath = resolve(options.bunPath ?? RELEASE_SERVICE_START_ADMISSION_BUN_PATH);
  const trustedAncestorBoundary = resolve(options.trustedAncestorBoundary ?? "/");
  const expectedUid = options.expectedUid ?? 0;
  const expectedGid = options.expectedGid ?? 0;

  assertRootOwnedAncestorChain(helperPath, trustedAncestorBoundary, expectedUid, expectedGid);
  assertRootOwnedAncestorChain(wrapperPath, trustedAncestorBoundary, expectedUid, expectedGid);
  assertRootOwnedAncestorChain(dropInPath, trustedAncestorBoundary, expectedUid, expectedGid);
  assertRootOwnedAncestorChain(bunPath, trustedAncestorBoundary, expectedUid, expectedGid);
  assertRootOwnedPath(helperPath, "file", 0o755, expectedUid, expectedGid);
  assertRootOwnedPath(wrapperPath, "file", 0o755, expectedUid, expectedGid);
  assertRootOwnedPath(dropInPath, "file", 0o644, expectedUid, expectedGid);
  assertRootOwnedPath(bunPath, "file", 0o755, expectedUid, expectedGid);

  const expectedBundle = await buildReleaseServiceStartAdmissionBundle(sourceRoot);
  const helperSha256 = sha256(readFileSync(helperPath));
  if (helperSha256 !== expectedBundle.sha256) {
    throw new Error("Installed release-start helper does not match the current reviewed source bundle");
  }
  const expectedWrapperBundle = await buildReleaseServiceWrapperBundle(sourceRoot);
  const wrapperSha256 = sha256(readFileSync(wrapperPath));
  if (wrapperSha256 !== expectedWrapperBundle.sha256) {
    throw new Error("Installed service wrapper does not match the current reviewed source bundle");
  }
  const expectedDropIn = readFileSync(
    join(sourceRoot, "deployment/systemd/ti-scale.service.d/10-release-start-admission.conf"),
  );
  const installedDropIn = readFileSync(dropInPath);
  const expectedDropInSha256 = sha256(expectedDropIn);
  const dropInSha256 = sha256(installedDropIn);
  if (dropInSha256 !== expectedDropInSha256) {
    throw new Error("Installed release-start systemd drop-in does not match reviewed source");
  }
  return Object.freeze({
    schemaVersion: "ti-scale.release-service-start-admission-installation.v2",
    helperSha256,
    wrapperSha256,
    dropInSha256,
  });
}
