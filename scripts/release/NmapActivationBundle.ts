import { createHash } from "node:crypto";
import {
  chmodSync,
  chownSync,
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
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { LocalToolCapabilityManifest } from "../../server/local-tools/LocalToolCapabilityManifest";

export const NMAP_ACTIVATION_BUNDLE_SCHEMA_VERSION =
  "ti-scale.nmap-activation-bundle.v1" as const;
export const NMAP_ACTIVATION_BUNDLE_VERSION =
  "nmap-safe-recon-2026.07.20-v3" as const;
export const NMAP_ACTIVATION_SERVICE_UNIT = "ti-scale.service" as const;
export const NMAP_ACTIVATION_DROP_IN_NAME =
  "60-reviewed-nmap-activation.conf" as const;
export const NMAP_ACTIVATION_DESCRIPTOR_RELATIVE_PATH =
  "deployment/runtime-config/nmap-activation-bundle.v1.json" as const;
export const NMAP_ACTIVATION_DESCRIPTOR_SHA256 =
  "2d78bae8c68961a95d63fc6483b77fc83c0acd7ce9024d1435fd6a0152ba04f4" as const;
export const NMAP_ACTIVATION_MUTATION_DISABLED_ERROR =
  "Reviewed Nmap activation install and rollback are disabled by the operator no-backup policy; use read-only verification" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const KNOWN_V2_DROP_IN = [
  "[Service]",
  "EnvironmentFile=/etc/ti-scale/runtime/bundles/nmap-guided-2026.07.20-v2/activation-environment.v2.conf",
  "",
].join("\n");
const KNOWN_V2_DROP_IN_SHA256 =
  "34f33a7584f092a2ffbda231ae1b5b7908f5ca71740e11cc133ea7315bec63ba" as const;
const UPGRADE_BACKUP_NAME = "prior-reviewed-nmap-drop-in.v2.conf" as const;
const UPGRADE_RECEIPT_NAME = "drop-in-upgrade-receipt.v1.json" as const;
const EXPECTED_DOCUMENT_ROLES = Object.freeze([
  "local_tool_capability_manifest",
  "local_tool_probe_sandbox",
  "engagement_workspace_mappings",
  "autonomous_dns_runtime",
  "activation_environment",
] as const);
const REVIEWED_FULL_TCP_FORWARD_COMPOSITION_ID =
  "autonomous-general-safe-recon-local-2026.07.22-v1" as const;

type DocumentRole = typeof EXPECTED_DOCUMENT_ROLES[number];

export interface ActivationBundleDocument {
  readonly role: DocumentRole;
  readonly sourcePath: string;
  readonly installName: string;
  readonly sha256: string;
  readonly sourceMode: number;
  readonly installMode: number;
}

export interface NmapActivationBundleDescriptor {
  readonly schemaVersion: typeof NMAP_ACTIVATION_BUNDLE_SCHEMA_VERSION;
  readonly bundleVersion: typeof NMAP_ACTIVATION_BUNDLE_VERSION;
  readonly serviceUnit: typeof NMAP_ACTIVATION_SERVICE_UNIT;
  readonly installRoot: "/etc/ti-scale/runtime/bundles";
  readonly dropInDirectory: "/etc/systemd/system/ti-scale.service.d";
  readonly dropInName: typeof NMAP_ACTIVATION_DROP_IN_NAME;
  readonly documents: readonly ActivationBundleDocument[];
  readonly dropIn: Readonly<{
    readonly sourcePath: string;
    readonly sha256: string;
    readonly sourceMode: number;
    readonly installMode: number;
  }>;
  readonly nmap: Readonly<{
    readonly installerPath: string;
    readonly installerSha256: string;
    readonly installerMode: number;
    readonly executablePath: string;
    readonly executableSha256: string;
  }>;
}

export interface ActiveV2WorkSnapshot {
  readonly activeRuns: readonly { readonly id: string; readonly status: string }[];
  readonly activeLeases: readonly { readonly runId: string; readonly expiresAt: string }[];
}

export interface NmapBinaryIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
  readonly fileCapabilities: "none" | string;
  readonly regularFile: boolean;
  readonly symbolicLink: boolean;
}

export interface ReviewedNmapInstallerPort {
  install(installerPath: string): Promise<NmapBinaryIdentity>;
  verify(installerPath: string): Promise<NmapBinaryIdentity>;
}

export interface TiScaleServiceIdentity {
  readonly id: string;
  readonly loadState: string;
  readonly activeState: string;
  readonly mainPid: number;
  readonly fragmentPath: string;
}

export interface TiScaleServiceController {
  identity(): Promise<TiScaleServiceIdentity>;
  stop(unit: typeof NMAP_ACTIVATION_SERVICE_UNIT): Promise<void>;
  daemonReload(): Promise<void>;
  start(unit: typeof NMAP_ACTIVATION_SERVICE_UNIT): Promise<void>;
}

export interface NmapActivationPostStartVerifier {
  /** Proves liveness, rich execution readiness, and the fresh exact Nmap dependency set. */
  verifyActivated(toolId: "kali:nmap-tcp-connect-service-scan"): Promise<void>;
  /** Proves the prior application is healthy after activation withdrawal. */
  verifyPriorServiceHealthy(): Promise<void>;
}

export interface NmapActivationBundleInstallerOptions {
  readonly sourceRoot: string;
  readonly descriptorRelativePath?: string;
  readonly descriptorSha256?: string;
  readonly sourceOwnerUid?: number;
  readonly installedOwnerUid?: number;
  readonly installedGroupGid: number;
  readonly bundleInstallRoot?: string;
  readonly dropInDirectory?: string;
  readonly readActiveWork: () => ActiveV2WorkSnapshot;
  readonly nmapInstaller: ReviewedNmapInstallerPort;
  readonly service: TiScaleServiceController;
  readonly postStartVerifier: NmapActivationPostStartVerifier;
  readonly clock?: () => Date;
  /**
   * Exact forward compositions are accepted only by read-only verification.
   * This injection point exists so tests can prove the composition boundary
   * without depending on production `/etc` content.
   */
  readonly installedForwardCompositions?: readonly NmapInstalledForwardComposition[];
}

export interface NmapInstalledForwardComposition {
  readonly id: string;
  readonly activationEnvironmentSha256: string;
  readonly manifestRelativePath: string;
  readonly manifestSha256: string;
  readonly manifestVersion: string;
  readonly runtimeRelativePath: string;
  readonly runtimeSha256: string;
  readonly runtimeConfigurationVersion: string;
}

export interface NmapActivationBundleResult {
  readonly bundleVersion: typeof NMAP_ACTIVATION_BUNDLE_VERSION;
  readonly status: "activated" | "rolled_back";
  readonly bundleDirectory: string;
  readonly dropInPath: string;
  readonly documents: readonly { readonly role: DocumentRole; readonly sha256: string }[];
  readonly controlsOnly: typeof NMAP_ACTIVATION_SERVICE_UNIT;
}

const REVIEWED_INSTALLED_FORWARD_COMPOSITIONS = Object.freeze([
  Object.freeze({
    id: REVIEWED_FULL_TCP_FORWARD_COMPOSITION_ID,
    activationEnvironmentSha256:
      "e5626e1ab932b16d5a6dc8b946f7f754cbb2952d81eda977ff25d556071749f3",
    manifestRelativePath:
      "full-tcp-20260722-v1/local-tool-capabilities.v1.json",
    manifestSha256:
      "03f40b824e948aa9110ad40210933ef0b15a553d695af183154221ad7c40a848",
    manifestVersion: "kali-local-general-safe-recon-2026.07.22-v1",
    runtimeRelativePath:
      "full-tcp-20260722-v1/autonomous-dns-local-runtime.v1.json",
    runtimeSha256:
      "b8bfad3aa83aff4bc8ea95835e5bfdde1d199fec86b1795d63f0c5c6482af5f4",
    runtimeConfigurationVersion: REVIEWED_FULL_TCP_FORWARD_COMPOSITION_ID,
  }),
] satisfies readonly NmapInstalledForwardComposition[]);

interface PreparedBundle {
  readonly descriptor: NmapActivationBundleDescriptor;
  readonly descriptorSha256: string;
  readonly documents: ReadonlyMap<DocumentRole, Buffer>;
  readonly dropIn: Buffer;
  readonly installerPath: string;
}

type DropInState = Readonly<
  | { kind: "absent" }
  | { kind: "known_v2"; bytes: Buffer }
  | { kind: "v3"; bytes: Buffer }
>;

type RecordedDropInPrior = "absent" | "known_v2";

interface InstalledFileSnapshot {
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
}

function sha256(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function readInstalledFileSnapshot(path: string): InstalledFileSnapshot {
  const before = lstatSync(path, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile()) {
    throw new Error(`Installed activation path is not a regular file: ${path}`);
  }
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size
      || before.mtimeNs !== opened.mtimeNs || before.ctimeNs !== opened.ctimeNs) {
      throw new Error(`Installed activation path changed before it was read: ${path}`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs || opened.ctimeNs !== after.ctimeNs) {
      throw new Error(`Installed activation path changed while it was read: ${path}`);
    }
    return Object.freeze({
      bytes,
      sha256: sha256(bytes),
      uid: Number(opened.uid),
      gid: Number(opened.gid),
      mode: Number(opened.mode & 0o7777n),
    });
  } finally {
    closeSync(descriptor);
  }
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} must contain exactly ${expected.join(", ")}`);
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function exactMode(value: unknown, expected: number, label: string): number {
  if (value !== expected) throw new Error(`${label} must be mode ${expected.toString(8)}`);
  return expected;
}

function relativeSourcePath(value: unknown, label: string): string {
  if (typeof value !== "string" || !value || value.includes("\0") || value.includes("\\")
    || isAbsolute(value) || value.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error(`${label} must be a safe repository-relative path`);
  }
  return value;
}

function installName(value: unknown, label: string): string {
  if (typeof value !== "string" || !SAFE_NAME.test(value) || value === "." || value === "..") {
    throw new Error(`${label} must be a safe single filename`);
  }
  return value;
}

function parseDescriptor(value: unknown): NmapActivationBundleDescriptor {
  const input = record(value, "Nmap activation bundle descriptor");
  exactKeys(input, [
    "bundleVersion", "documents", "dropIn", "dropInDirectory", "dropInName",
    "installRoot", "nmap", "schemaVersion", "serviceUnit",
  ], "Nmap activation bundle descriptor");
  if (input.schemaVersion !== NMAP_ACTIVATION_BUNDLE_SCHEMA_VERSION
    || input.bundleVersion !== NMAP_ACTIVATION_BUNDLE_VERSION
    || input.serviceUnit !== NMAP_ACTIVATION_SERVICE_UNIT
    || input.installRoot !== "/etc/ti-scale/runtime/bundles"
    || input.dropInDirectory !== "/etc/systemd/system/ti-scale.service.d"
    || input.dropInName !== NMAP_ACTIVATION_DROP_IN_NAME) {
    throw new Error("Nmap activation bundle identity or production boundary is invalid");
  }
  if (!Array.isArray(input.documents) || input.documents.length !== EXPECTED_DOCUMENT_ROLES.length) {
    throw new Error("Nmap activation bundle requires exactly five runtime documents");
  }
  const documents = input.documents.map((raw, index): ActivationBundleDocument => {
    const document = record(raw, `Nmap activation document ${index + 1}`);
    exactKeys(document, [
      "installMode", "installName", "role", "sha256", "sourceMode", "sourcePath",
    ], `Nmap activation document ${index + 1}`);
    if (!(EXPECTED_DOCUMENT_ROLES as readonly unknown[]).includes(document.role)) {
      throw new Error(`Nmap activation document ${index + 1} has an unknown role`);
    }
    return Object.freeze({
      role: document.role as DocumentRole,
      sourcePath: relativeSourcePath(document.sourcePath, `Document ${index + 1} sourcePath`),
      installName: installName(document.installName, `Document ${index + 1} installName`),
      sha256: digest(document.sha256, `Document ${index + 1} sha256`),
      sourceMode: exactMode(document.sourceMode, 0o644, `Document ${index + 1} sourceMode`),
      installMode: exactMode(document.installMode, 0o440, `Document ${index + 1} installMode`),
    });
  });
  if (new Set(documents.map(({ role }) => role)).size !== documents.length
    || EXPECTED_DOCUMENT_ROLES.some((role) => !documents.some((document) => document.role === role))
    || new Set(documents.map(({ installName: name }) => name)).size !== documents.length) {
    throw new Error("Nmap activation document roles and install names must be complete and unique");
  }

  const dropIn = record(input.dropIn, "Nmap activation systemd drop-in");
  exactKeys(dropIn, ["installMode", "sha256", "sourceMode", "sourcePath"], "Nmap activation systemd drop-in");
  const nmap = record(input.nmap, "Nmap activation executable");
  exactKeys(nmap, [
    "executablePath", "executableSha256", "installerMode", "installerPath", "installerSha256",
  ], "Nmap activation executable");
  const descriptor: NmapActivationBundleDescriptor = {
    schemaVersion: NMAP_ACTIVATION_BUNDLE_SCHEMA_VERSION,
    bundleVersion: NMAP_ACTIVATION_BUNDLE_VERSION,
    serviceUnit: NMAP_ACTIVATION_SERVICE_UNIT,
    installRoot: "/etc/ti-scale/runtime/bundles",
    dropInDirectory: "/etc/systemd/system/ti-scale.service.d",
    dropInName: NMAP_ACTIVATION_DROP_IN_NAME,
    documents: Object.freeze(documents),
    dropIn: Object.freeze({
      sourcePath: relativeSourcePath(dropIn.sourcePath, "Drop-in sourcePath"),
      sha256: digest(dropIn.sha256, "Drop-in sha256"),
      sourceMode: exactMode(dropIn.sourceMode, 0o644, "Drop-in sourceMode"),
      installMode: exactMode(dropIn.installMode, 0o644, "Drop-in installMode"),
    }),
    nmap: Object.freeze({
      installerPath: relativeSourcePath(nmap.installerPath, "Nmap installerPath"),
      installerSha256: digest(nmap.installerSha256, "Nmap installerSha256"),
      installerMode: exactMode(nmap.installerMode, 0o755, "Nmap installerMode"),
      executablePath: typeof nmap.executablePath === "string" ? nmap.executablePath : "",
      executableSha256: digest(nmap.executableSha256, "Nmap executableSha256"),
    }),
  };
  if (descriptor.nmap.executablePath
    !== "/opt/ti-scale-toolchain/nmap/5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f/nmap"
    || descriptor.nmap.executableSha256
      !== "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f") {
    throw new Error("Nmap activation bundle executable identity is not the reviewed binding");
  }
  return Object.freeze(descriptor);
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`));
}

function assertDirectory(path: string, ownerUid: number, label: string): void {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a real directory`);
  }
  if (metadata.uid !== ownerUid || (metadata.mode & 0o022) !== 0) {
    throw new Error(`${label} must have the reviewed owner and must not be group/world writable`);
  }
}

function readPinnedFile(input: Readonly<{
  sourceRoot: string;
  relativePath: string;
  expectedSha256: string;
  expectedMode: number;
  ownerUid: number;
}>): Buffer {
  const root = resolve(input.sourceRoot);
  const path = resolve(root, input.relativePath);
  if (!containedBy(root, path) || path === root) throw new Error("Pinned source path escapes its source root");
  assertDirectory(root, input.ownerUid, "Pinned source root");
  const segments = relative(root, path).split(sep).filter(Boolean);
  let current = root;
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment);
    const metadata = lstatSync(current);
    const final = index === segments.length - 1;
    if (metadata.isSymbolicLink() || (final ? !metadata.isFile() : !metadata.isDirectory())) {
      throw new Error(`Pinned source ${input.relativePath} contains a symlink or non-regular entry`);
    }
    if (metadata.uid !== input.ownerUid || (metadata.mode & 0o022) !== 0) {
      throw new Error(`Pinned source ${input.relativePath} has an untrusted owner or writable path component`);
    }
    if (final && (metadata.mode & 0o7777) !== input.expectedMode) {
      throw new Error(`Pinned source ${input.relativePath} mode drifted from ${input.expectedMode.toString(8)}`);
    }
  }
  const before = lstatSync(path, { bigint: true });
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size
      || before.mtimeNs !== opened.mtimeNs || before.ctimeNs !== opened.ctimeNs) {
      throw new Error(`Pinned source ${input.relativePath} changed before it was read`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs || opened.ctimeNs !== after.ctimeNs) {
      throw new Error(`Pinned source ${input.relativePath} changed while it was read`);
    }
    if (sha256(bytes) !== input.expectedSha256) {
      throw new Error(`Pinned source ${input.relativePath} does not match its reviewed SHA-256`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function byRole(descriptor: NmapActivationBundleDescriptor, role: DocumentRole): ActivationBundleDocument {
  const document = descriptor.documents.find((entry) => entry.role === role);
  if (!document) throw new Error(`Nmap activation bundle is missing ${role}`);
  return document;
}

function expectedDropIn(descriptor: NmapActivationBundleDescriptor): string {
  const bundleRoot = `${descriptor.installRoot}/${descriptor.bundleVersion}`;
  const environment = byRole(descriptor, "activation_environment");
  return [
    "[Service]",
    // systemd EnvironmentFile values override Environment= values regardless
    // of directive order. Loading one later, checksum-bound environment file
    // is therefore the only reviewed way to override the base service file
    // without copying its unrelated settings or secrets.
    `EnvironmentFile=${bundleRoot}/${environment.installName}`,
    "",
  ].join("\n");
}

function expectedActivationEnvironment(descriptor: NmapActivationBundleDescriptor): string {
  const bundleRoot = `${descriptor.installRoot}/${descriptor.bundleVersion}`;
  const manifest = byRole(descriptor, "local_tool_capability_manifest");
  const sandbox = byRole(descriptor, "local_tool_probe_sandbox");
  const workspaces = byRole(descriptor, "engagement_workspace_mappings");
  const autonomous = byRole(descriptor, "autonomous_dns_runtime");
  return [
    `TI_SCALE_LOCAL_TOOL_TRUSTED_CONFIG_ROOT=${bundleRoot}`,
    `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_PATH=${bundleRoot}/${manifest.installName}`,
    `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256=${manifest.sha256}`,
    `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_PATH=${bundleRoot}/${sandbox.installName}`,
    `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_SHA256=${sandbox.sha256}`,
    `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_PATH=${bundleRoot}/${workspaces.installName}`,
    `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_SHA256=${workspaces.sha256}`,
    `TI_SCALE_AUTONOMOUS_DNS_TRUSTED_CONFIG_ROOT=${bundleRoot}`,
    `TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_PATH=${bundleRoot}/${autonomous.installName}`,
    `TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_SHA256=${autonomous.sha256}`,
    "",
  ].join("\n");
}

function normalizeInstalledForwardComposition(
  value: NmapInstalledForwardComposition,
  index: number,
): NmapInstalledForwardComposition {
  const label = `Installed Nmap forward composition ${index + 1}`;
  if (typeof value.id !== "string" || !SAFE_NAME.test(value.id)) {
    throw new Error(`${label} id must be a safe stable identifier`);
  }
  const manifestRelativePath = relativeSourcePath(
    value.manifestRelativePath,
    `${label} manifestRelativePath`,
  );
  const runtimeRelativePath = relativeSourcePath(
    value.runtimeRelativePath,
    `${label} runtimeRelativePath`,
  );
  if (manifestRelativePath === runtimeRelativePath
    || !manifestRelativePath.endsWith("/local-tool-capabilities.v1.json")
    || !runtimeRelativePath.endsWith("/autonomous-dns-local-runtime.v1.json")
    || dirname(manifestRelativePath) !== dirname(runtimeRelativePath)) {
    throw new Error(`${label} must bind one colocated manifest/runtime pair`);
  }
  if (typeof value.manifestVersion !== "string" || !value.manifestVersion
    || typeof value.runtimeConfigurationVersion !== "string"
    || !value.runtimeConfigurationVersion) {
    throw new Error(`${label} requires exact manifest and runtime versions`);
  }
  return Object.freeze({
    id: value.id,
    activationEnvironmentSha256: digest(
      value.activationEnvironmentSha256,
      `${label} activationEnvironmentSha256`,
    ),
    manifestRelativePath,
    manifestSha256: digest(value.manifestSha256, `${label} manifestSha256`),
    manifestVersion: value.manifestVersion,
    runtimeRelativePath,
    runtimeSha256: digest(value.runtimeSha256, `${label} runtimeSha256`),
    runtimeConfigurationVersion: value.runtimeConfigurationVersion,
  });
}

function expectedForwardActivationEnvironment(
  descriptor: NmapActivationBundleDescriptor,
  composition: NmapInstalledForwardComposition,
): Buffer {
  const bundleRoot = `${descriptor.installRoot}/${descriptor.bundleVersion}`;
  const sandbox = byRole(descriptor, "local_tool_probe_sandbox");
  const workspaces = byRole(descriptor, "engagement_workspace_mappings");
  const expected = Buffer.from([
    `TI_SCALE_LOCAL_TOOL_TRUSTED_CONFIG_ROOT=${bundleRoot}`,
    `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_PATH=${bundleRoot}/${composition.manifestRelativePath}`,
    `TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256=${composition.manifestSha256}`,
    `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_PATH=${bundleRoot}/${sandbox.installName}`,
    `TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_SHA256=${sandbox.sha256}`,
    `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_PATH=${bundleRoot}/${workspaces.installName}`,
    `TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_SHA256=${workspaces.sha256}`,
    `TI_SCALE_AUTONOMOUS_DNS_TRUSTED_CONFIG_ROOT=${bundleRoot}`,
    `TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_PATH=${bundleRoot}/${composition.runtimeRelativePath}`,
    `TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_SHA256=${composition.runtimeSha256}`,
    "",
  ].join("\n"), "utf8");
  if (sha256(expected) !== composition.activationEnvironmentSha256) {
    expected.fill(0);
    throw new Error(
      `Installed Nmap forward composition ${composition.id} has an invalid source identity`,
    );
  }
  return expected;
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function ensureDirectory(path: string, ownerUid: number, groupGid: number, mode: number): void {
  const parent = dirname(path);
  if (parent !== path && !existsSync(parent)) ensureDirectory(parent, ownerUid, groupGid, mode);
  if (!existsSync(path)) {
    mkdirSync(path, { mode });
    chownSync(path, ownerUid, groupGid);
    chmodSync(path, mode);
  }
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || metadata.uid !== ownerUid
    || metadata.gid !== groupGid || (metadata.mode & 0o7777) !== mode) {
    throw new Error(`Activation destination directory is not the exact root-owned boundary: ${path}`);
  }
}

function verifyInstalledFile(
  path: string,
  expectedSha256: string,
  ownerUid: number,
  groupGid: number,
  mode: number,
): void {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.uid !== ownerUid
    || metadata.gid !== groupGid || (metadata.mode & 0o7777) !== mode
    || sha256(readFileSync(path)) !== expectedSha256) {
    throw new Error(`Installed activation file failed exact identity verification: ${path}`);
  }
}

function writeInstalledFile(
  path: string,
  bytes: Buffer,
  ownerUid: number,
  groupGid: number,
  mode: number,
): void {
  writeFileSync(path, bytes, { flag: "wx", mode });
  chownSync(path, ownerUid, groupGid);
  chmodSync(path, mode);
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function writeInstalledFileAtomically(
  path: string,
  bytes: Buffer,
  ownerUid: number,
  groupGid: number,
  mode: number,
  clock: () => Date,
): void {
  const temporary = join(
    dirname(path),
    `.${path.split("/").at(-1) ?? "activation"}.${process.pid}.${clock().getTime()}.tmp`,
  );
  try {
    writeInstalledFile(temporary, bytes, ownerUid, groupGid, mode);
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

function assertNoActiveWork(snapshot: ActiveV2WorkSnapshot): void {
  if (snapshot.activeRuns.length || snapshot.activeLeases.length) {
    throw new Error("Ti-Scale has active V2 work; Nmap activation is refused until runs and leases are durably inactive");
  }
}

function assertBinaryIdentity(
  actual: NmapBinaryIdentity,
  descriptor: NmapActivationBundleDescriptor,
): void {
  if (actual.path !== descriptor.nmap.executablePath
    || actual.sha256 !== descriptor.nmap.executableSha256
    || actual.uid !== 0 || actual.gid !== 0 || actual.mode !== 0o555
    || actual.fileCapabilities !== "none" || !actual.regularFile || actual.symbolicLink) {
    throw new Error("Reviewed Nmap installer returned the wrong binary identity");
  }
}

function assertServiceIdentity(identity: TiScaleServiceIdentity, expectedState: "active" | "inactive"): void {
  if (identity.id !== NMAP_ACTIVATION_SERVICE_UNIT || identity.loadState !== "loaded"
    || identity.fragmentPath !== "/etc/systemd/system/ti-scale.service"
    || identity.activeState !== expectedState
    || (expectedState === "active" ? identity.mainPid <= 0 : identity.mainPid !== 0)) {
    throw new Error("Systemd service identity does not match the exact Ti-Scale service boundary");
  }
}

export class NmapActivationBundleInstaller {
  readonly #sourceRoot: string;
  readonly #descriptorRelativePath: string;
  readonly #descriptorSha256: string;
  readonly #sourceOwnerUid: number;
  readonly #installedOwnerUid: number;
  readonly #installedGroupGid: number;
  readonly #bundleInstallRoot: string;
  readonly #dropInDirectory: string;
  readonly #readActiveWork: () => ActiveV2WorkSnapshot;
  readonly #nmapInstaller: ReviewedNmapInstallerPort;
  readonly #service: TiScaleServiceController;
  readonly #postStartVerifier: NmapActivationPostStartVerifier;
  readonly #clock: () => Date;
  readonly #installedForwardCompositions: readonly NmapInstalledForwardComposition[];

  constructor(options: NmapActivationBundleInstallerOptions) {
    this.#sourceRoot = resolve(options.sourceRoot);
    this.#descriptorRelativePath = options.descriptorRelativePath
      ?? NMAP_ACTIVATION_DESCRIPTOR_RELATIVE_PATH;
    this.#descriptorSha256 = options.descriptorSha256
      ?? NMAP_ACTIVATION_DESCRIPTOR_SHA256;
    this.#sourceOwnerUid = options.sourceOwnerUid ?? 0;
    this.#installedOwnerUid = options.installedOwnerUid ?? 0;
    this.#installedGroupGid = options.installedGroupGid;
    this.#bundleInstallRoot = resolve(options.bundleInstallRoot
      ?? "/etc/ti-scale/runtime/bundles");
    this.#dropInDirectory = resolve(options.dropInDirectory
      ?? "/etc/systemd/system/ti-scale.service.d");
    this.#readActiveWork = options.readActiveWork;
    this.#nmapInstaller = options.nmapInstaller;
    this.#service = options.service;
    this.#postStartVerifier = options.postStartVerifier;
    this.#clock = options.clock ?? (() => new Date());
    this.#installedForwardCompositions = Object.freeze(
      [...(options.installedForwardCompositions
        ?? REVIEWED_INSTALLED_FORWARD_COMPOSITIONS)]
        .map(normalizeInstalledForwardComposition),
    );
    if (new Set(this.#installedForwardCompositions.map(({ id }) => id)).size
      !== this.#installedForwardCompositions.length) {
      throw new Error("Installed Nmap forward composition ids must be unique");
    }
  }

  #prepare(): PreparedBundle {
    const descriptorBytes = readPinnedFile({
      sourceRoot: this.#sourceRoot,
      relativePath: this.#descriptorRelativePath,
      expectedSha256: this.#descriptorSha256,
      expectedMode: 0o644,
      ownerUid: this.#sourceOwnerUid,
    });
    let descriptorValue: unknown;
    try { descriptorValue = JSON.parse(descriptorBytes.toString("utf8")) as unknown; }
    catch { throw new Error("Nmap activation bundle descriptor is not valid JSON"); }
    const descriptor = parseDescriptor(descriptorValue);
    const documents = new Map<DocumentRole, Buffer>();
    for (const document of descriptor.documents) {
      documents.set(document.role, readPinnedFile({
        sourceRoot: this.#sourceRoot,
        relativePath: document.sourcePath,
        expectedSha256: document.sha256,
        expectedMode: document.sourceMode,
        ownerUid: this.#sourceOwnerUid,
      }));
    }
    const manifestDocument = JSON.parse(
      documents.get("local_tool_capability_manifest")!.toString("utf8"),
    ) as unknown;
    const manifest = new LocalToolCapabilityManifest(manifestDocument);
    const nmap = manifest.resolve("kali:nmap-tcp-connect-service-scan");
    if (manifest.descriptor.manifestVersion !== "kali-local-nmap-enabled-2026.07.20-v1"
      || !nmap || nmap.activation !== "enabled" || nmap.activationReason !== null
      || nmap.executable.path !== descriptor.nmap.executablePath
      || nmap.executable.expectedSha256 !== descriptor.nmap.executableSha256) {
      throw new Error("Pinned capability manifest does not contain the exact enabled Nmap binding");
    }
    const activationEnvironment = documents.get("activation_environment")!;
    if (activationEnvironment.toString("utf8") !== expectedActivationEnvironment(descriptor)) {
      throw new Error("Pinned activation environment is not the exact secret-free five-document Ti-Scale boundary");
    }
    const dropIn = readPinnedFile({
      sourceRoot: this.#sourceRoot,
      relativePath: descriptor.dropIn.sourcePath,
      expectedSha256: descriptor.dropIn.sha256,
      expectedMode: descriptor.dropIn.sourceMode,
      ownerUid: this.#sourceOwnerUid,
    });
    if (dropIn.toString("utf8") !== expectedDropIn(descriptor)) {
      throw new Error("Pinned systemd drop-in does not load the exact later activation environment file");
    }
    const installerBytes = readPinnedFile({
      sourceRoot: this.#sourceRoot,
      relativePath: descriptor.nmap.installerPath,
      expectedSha256: descriptor.nmap.installerSha256,
      expectedMode: descriptor.nmap.installerMode,
      ownerUid: this.#sourceOwnerUid,
    });
    if (!installerBytes.toString("utf8").includes("set -Eeuo pipefail")) {
      throw new Error("Pinned Nmap installer is not the reviewed fail-closed script");
    }
    return Object.freeze({
      descriptor,
      descriptorSha256: this.#descriptorSha256,
      documents,
      dropIn,
      installerPath: resolve(this.#sourceRoot, descriptor.nmap.installerPath),
    });
  }

  #bundleDirectory(descriptor: NmapActivationBundleDescriptor): string {
    return join(this.#bundleInstallRoot, descriptor.bundleVersion);
  }

  #dropInPath(descriptor: NmapActivationBundleDescriptor): string {
    return join(this.#dropInDirectory, descriptor.dropInName);
  }

  #verifyForwardComposition(
    prepared: PreparedBundle,
    activation: InstalledFileSnapshot,
  ): boolean {
    const bundleDirectory = this.#bundleDirectory(prepared.descriptor);
    for (const composition of this.#installedForwardCompositions) {
      if (activation.sha256 !== composition.activationEnvironmentSha256) continue;
      const expectedEnvironment = expectedForwardActivationEnvironment(
        prepared.descriptor,
        composition,
      );
      try {
        if (!activation.bytes.equals(expectedEnvironment)) continue;
      } finally {
        expectedEnvironment.fill(0);
      }

      const compositionDirectory = join(
        bundleDirectory,
        dirname(composition.manifestRelativePath),
      );
      if (!containedBy(bundleDirectory, compositionDirectory)
        || compositionDirectory === bundleDirectory) {
        throw new Error(
          `Installed Nmap forward composition ${composition.id} escapes its bundle`,
        );
      }
      const directory = lstatSync(compositionDirectory);
      if (directory.isSymbolicLink() || !directory.isDirectory()
        || directory.uid !== this.#installedOwnerUid
        || directory.gid !== this.#installedGroupGid
        || (directory.mode & 0o7777) !== 0o750) {
        throw new Error(
          `Installed Nmap forward composition ${composition.id} directory identity is invalid`,
        );
      }
      const manifestPath = join(bundleDirectory, composition.manifestRelativePath);
      const runtimePath = join(bundleDirectory, composition.runtimeRelativePath);
      verifyInstalledFile(
        manifestPath,
        composition.manifestSha256,
        this.#installedOwnerUid,
        this.#installedGroupGid,
        0o440,
      );
      verifyInstalledFile(
        runtimePath,
        composition.runtimeSha256,
        this.#installedOwnerUid,
        this.#installedGroupGid,
        0o440,
      );

      let manifestValue: unknown;
      let runtimeValue: unknown;
      try {
        manifestValue = JSON.parse(readFileSync(manifestPath, "utf8")) as unknown;
        runtimeValue = JSON.parse(readFileSync(runtimePath, "utf8")) as unknown;
      } catch {
        throw new Error(
          `Installed Nmap forward composition ${composition.id} is not valid JSON`,
        );
      }
      const manifest = new LocalToolCapabilityManifest(manifestValue);
      const nmap = manifest.resolve("kali:nmap-tcp-connect-service-scan");
      if (manifest.descriptor.manifestVersion !== composition.manifestVersion
        || !nmap || nmap.activation !== "enabled" || nmap.activationReason !== null
        || nmap.executable.path !== prepared.descriptor.nmap.executablePath
        || nmap.executable.expectedSha256
          !== prepared.descriptor.nmap.executableSha256) {
        throw new Error(
          `Installed Nmap forward composition ${composition.id} changed the reviewed Nmap binding`,
        );
      }
      const runtime = record(
        runtimeValue,
        `Installed Nmap forward composition ${composition.id} runtime`,
      );
      const fullTcpBaseline = record(
        runtime.fullTcpBaseline,
        `Installed Nmap forward composition ${composition.id} fullTcpBaseline`,
      );
      if (runtime.schemaVersion
          !== "ti-scale.autonomous-dns-runtime-configuration.v1"
        || runtime.configurationVersion
          !== composition.runtimeConfigurationVersion
        || fullTcpBaseline?.bindingId
          !== "binding:autonomous-full-tcp-baseline-v1") {
        throw new Error(
          `Installed Nmap forward composition ${composition.id} runtime identity is invalid`,
        );
      }
      return true;
    }
    return false;
  }

  #verifyBundle(prepared: PreparedBundle): void {
    const directory = this.#bundleDirectory(prepared.descriptor);
    const metadata = lstatSync(directory);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()
      || metadata.uid !== this.#installedOwnerUid || metadata.gid !== this.#installedGroupGid
      || (metadata.mode & 0o7777) !== 0o750) {
      throw new Error("Installed Nmap activation bundle directory identity is invalid");
    }
    for (const document of prepared.descriptor.documents) {
      const path = join(directory, document.installName);
      if (document.role === "activation_environment") {
        const activation = readInstalledFileSnapshot(path);
        if (activation.uid !== this.#installedOwnerUid
          || activation.gid !== this.#installedGroupGid
          || activation.mode !== document.installMode
          || (activation.sha256 !== document.sha256
            && !this.#verifyForwardComposition(prepared, activation))) {
          throw new Error(
            `Installed activation file failed exact identity verification: ${path}`,
          );
        }
        continue;
      }
      verifyInstalledFile(
        path,
        document.sha256,
        this.#installedOwnerUid,
        this.#installedGroupGid,
        document.installMode,
      );
    }
  }

  #stageBundle(prepared: PreparedBundle): void {
    ensureDirectory(
      this.#bundleInstallRoot,
      this.#installedOwnerUid,
      this.#installedGroupGid,
      0o750,
    );
    const destination = this.#bundleDirectory(prepared.descriptor);
    if (existsSync(destination)) {
      this.#verifyBundle(prepared);
      return;
    }
    const staging = join(
      this.#bundleInstallRoot,
      `.stage-${prepared.descriptor.bundleVersion}-${process.pid}-${this.#clock().getTime()}`,
    );
    mkdirSync(staging, { mode: 0o750 });
    chownSync(staging, this.#installedOwnerUid, this.#installedGroupGid);
    chmodSync(staging, 0o750);
    try {
      for (const document of prepared.descriptor.documents) {
        writeInstalledFile(
          join(staging, document.installName),
          prepared.documents.get(document.role)!,
          this.#installedOwnerUid,
          this.#installedGroupGid,
          document.installMode,
        );
      }
      fsyncDirectory(staging);
      renameSync(staging, destination);
      fsyncDirectory(this.#bundleInstallRoot);
      this.#verifyBundle(prepared);
    } catch (error) {
      rmSync(staging, { recursive: true, force: true });
      throw error;
    }
  }

  #verifyDropIn(prepared: PreparedBundle): void {
    verifyInstalledFile(
      this.#dropInPath(prepared.descriptor),
      prepared.descriptor.dropIn.sha256,
      this.#installedOwnerUid,
      0,
      prepared.descriptor.dropIn.installMode,
    );
  }

  #dropInState(prepared: PreparedBundle): DropInState {
    const path = this.#dropInPath(prepared.descriptor);
    if (!existsSync(path)) return Object.freeze({ kind: "absent" });
    const snapshot = readInstalledFileSnapshot(path);
    if (snapshot.uid !== this.#installedOwnerUid || snapshot.gid !== 0
      || snapshot.mode !== prepared.descriptor.dropIn.installMode) {
      throw new Error("Existing Nmap activation drop-in has an unknown owner or mode; upgrade refused");
    }
    if (snapshot.sha256 === prepared.descriptor.dropIn.sha256
      && snapshot.bytes.equals(prepared.dropIn)) {
      return Object.freeze({ kind: "v3", bytes: snapshot.bytes });
    }
    if (snapshot.sha256 === KNOWN_V2_DROP_IN_SHA256
      && snapshot.bytes.equals(Buffer.from(KNOWN_V2_DROP_IN, "utf8"))) {
      return Object.freeze({ kind: "known_v2", bytes: snapshot.bytes });
    }
    throw new Error("Existing Nmap activation drop-in is neither reviewed v2 nor exact v3; upgrade refused");
  }

  #upgradeBackupPath(prepared: PreparedBundle): string {
    return join(this.#bundleDirectory(prepared.descriptor), UPGRADE_BACKUP_NAME);
  }

  #upgradeReceiptPath(prepared: PreparedBundle): string {
    return join(this.#bundleDirectory(prepared.descriptor), UPGRADE_RECEIPT_NAME);
  }

  #expectedUpgradeReceipt(prepared: PreparedBundle): Buffer {
    return Buffer.from(`${JSON.stringify({
      schemaVersion: "ti-scale.nmap-drop-in-upgrade-receipt.v1",
      bundleVersion: prepared.descriptor.bundleVersion,
      dropInName: prepared.descriptor.dropInName,
      prior: {
        reviewedVersion: "nmap-guided-2026.07.20-v2",
        sha256: KNOWN_V2_DROP_IN_SHA256,
        uid: this.#installedOwnerUid,
        gid: 0,
        mode: prepared.descriptor.dropIn.installMode,
        byteSize: Buffer.byteLength(KNOWN_V2_DROP_IN, "utf8"),
        backupName: UPGRADE_BACKUP_NAME,
      },
      replacement: {
        reviewedVersion: prepared.descriptor.bundleVersion,
        sha256: prepared.descriptor.dropIn.sha256,
      },
    }, null, 2)}\n`, "utf8");
  }

  #verifyUpgradeReceipt(prepared: PreparedBundle): void {
    const backup = readInstalledFileSnapshot(this.#upgradeBackupPath(prepared));
    if (backup.uid !== this.#installedOwnerUid || backup.gid !== 0 || backup.mode !== 0o400
      || backup.sha256 !== KNOWN_V2_DROP_IN_SHA256
      || !backup.bytes.equals(Buffer.from(KNOWN_V2_DROP_IN, "utf8"))) {
      throw new Error("The known-v2 drop-in backup receipt failed exact identity verification");
    }
    const expected = this.#expectedUpgradeReceipt(prepared);
    const receipt = readInstalledFileSnapshot(this.#upgradeReceiptPath(prepared));
    if (receipt.uid !== this.#installedOwnerUid || receipt.gid !== 0 || receipt.mode !== 0o400
      || receipt.sha256 !== sha256(expected) || !receipt.bytes.equals(expected)) {
      throw new Error("The known-v2 drop-in upgrade receipt failed exact identity verification");
    }
  }

  #recordedPrior(prepared: PreparedBundle): RecordedDropInPrior {
    const backupExists = existsSync(this.#upgradeBackupPath(prepared));
    const receiptExists = existsSync(this.#upgradeReceiptPath(prepared));
    if (!backupExists && !receiptExists) return "absent";
    if (!backupExists || !receiptExists) {
      throw new Error("The known-v2 drop-in upgrade receipt is incomplete; activation refused");
    }
    this.#verifyUpgradeReceipt(prepared);
    return "known_v2";
  }

  #prepareKnownV2UpgradeReceipt(prepared: PreparedBundle, prior: Buffer): void {
    if (sha256(prior) !== KNOWN_V2_DROP_IN_SHA256
      || !prior.equals(Buffer.from(KNOWN_V2_DROP_IN, "utf8"))) {
      throw new Error("The pre-replacement drop-in is not the exact reviewed v2 identity");
    }
    const backupPath = this.#upgradeBackupPath(prepared);
    const receiptPath = this.#upgradeReceiptPath(prepared);
    const backupExists = existsSync(backupPath);
    const receiptExists = existsSync(receiptPath);
    if (receiptExists && !backupExists) {
      throw new Error("The known-v2 drop-in upgrade receipt exists without its backup");
    }
    if (backupExists) {
      const backup = readInstalledFileSnapshot(backupPath);
      if (backup.uid !== this.#installedOwnerUid || backup.gid !== 0 || backup.mode !== 0o400
        || backup.sha256 !== KNOWN_V2_DROP_IN_SHA256 || !backup.bytes.equals(prior)) {
        throw new Error("The known-v2 pre-replacement backup has drifted");
      }
      if (receiptExists) {
        this.#verifyUpgradeReceipt(prepared);
        return;
      }
    } else {
      writeInstalledFileAtomically(
        backupPath,
        prior,
        this.#installedOwnerUid,
        0,
        0o400,
        this.#clock,
      );
    }
    writeInstalledFileAtomically(
      receiptPath,
      this.#expectedUpgradeReceipt(prepared),
      this.#installedOwnerUid,
      0,
      0o400,
      this.#clock,
    );
    this.#verifyUpgradeReceipt(prepared);
  }

  #publishDropIn(
    prepared: PreparedBundle,
    expectedPrior: RecordedDropInPrior,
  ): void {
    ensureDirectory(this.#dropInDirectory, this.#installedOwnerUid, 0, 0o755);
    const current = this.#dropInState(prepared);
    if ((expectedPrior === "absent" && current.kind !== "absent")
      || (expectedPrior === "known_v2" && current.kind !== "known_v2")) {
      throw new Error("The reviewed prior drop-in changed before atomic publication");
    }
    if (expectedPrior === "known_v2") this.#verifyUpgradeReceipt(prepared);
    writeInstalledFileAtomically(
      this.#dropInPath(prepared.descriptor),
      prepared.dropIn,
      this.#installedOwnerUid,
      0,
      prepared.descriptor.dropIn.installMode,
      this.#clock,
    );
    this.#verifyDropIn(prepared);
  }

  #restorePriorDropIn(prepared: PreparedBundle, prior: RecordedDropInPrior): void {
    if (this.#dropInState(prepared).kind !== "v3") {
      throw new Error("The activated v3 drop-in changed before prior-state restoration");
    }
    const destination = this.#dropInPath(prepared.descriptor);
    if (prior === "absent") {
      unlinkSync(destination);
      fsyncDirectory(this.#dropInDirectory);
      if (this.#dropInState(prepared).kind !== "absent") {
        throw new Error("The absent prior drop-in state was not restored exactly");
      }
      return;
    }
    this.#verifyUpgradeReceipt(prepared);
    const backup = readInstalledFileSnapshot(this.#upgradeBackupPath(prepared));
    writeInstalledFileAtomically(
      destination,
      backup.bytes,
      this.#installedOwnerUid,
      0,
      prepared.descriptor.dropIn.installMode,
      this.#clock,
    );
    if (this.#dropInState(prepared).kind !== "known_v2") {
      throw new Error("The reviewed v2 prior drop-in was not restored exactly");
    }
  }

  #publishPriorAtEmptyDestination(
    prepared: PreparedBundle,
    prior: RecordedDropInPrior,
  ): void {
    const destination = this.#dropInPath(prepared.descriptor);
    if (existsSync(destination)) throw new Error("Prior drop-in restore destination is not empty");
    if (prior === "absent") return;
    this.#verifyUpgradeReceipt(prepared);
    const backup = readInstalledFileSnapshot(this.#upgradeBackupPath(prepared));
    writeInstalledFileAtomically(
      destination,
      backup.bytes,
      this.#installedOwnerUid,
      0,
      prepared.descriptor.dropIn.installMode,
      this.#clock,
    );
    if (this.#dropInState(prepared).kind !== "known_v2") {
      throw new Error("The reviewed v2 prior drop-in was not restored exactly");
    }
  }

  #result(
    prepared: PreparedBundle,
    status: NmapActivationBundleResult["status"],
  ): NmapActivationBundleResult {
    return Object.freeze({
      bundleVersion: prepared.descriptor.bundleVersion,
      status,
      bundleDirectory: this.#bundleDirectory(prepared.descriptor),
      dropInPath: this.#dropInPath(prepared.descriptor),
      documents: Object.freeze(prepared.descriptor.documents.map(({ role, sha256: value }) => ({
        role,
        sha256: value,
      }))),
      controlsOnly: NMAP_ACTIVATION_SERVICE_UNIT,
    });
  }

  async install(): Promise<NmapActivationBundleResult> {
    if (NMAP_ACTIVATION_MUTATION_DISABLED_ERROR.length > 0) {
      throw new Error(NMAP_ACTIVATION_MUTATION_DISABLED_ERROR);
    }

    /* c8 ignore start -- unreachable retired implementation pending source removal */
    const prepared = this.#prepare();
    assertNoActiveWork(this.#readActiveWork());
    assertServiceIdentity(await this.#service.identity(), "active");

    // Binary installation always precedes configuration staging. The installer
    // itself cannot edit /etc, enable the manifest, or control a service.
    const installed = await this.#nmapInstaller.install(prepared.installerPath);
    assertBinaryIdentity(installed, prepared.descriptor);
    assertBinaryIdentity(
      await this.#nmapInstaller.verify(prepared.installerPath),
      prepared.descriptor,
    );
    this.#stageBundle(prepared);

    const initialDropIn = this.#dropInState(prepared);
    if (initialDropIn.kind === "v3") {
      // A repeated install is a verification operation, not another service
      // restart. Validate any retained v2 rollback receipt before proving the
      // currently running v3 boundary.
      this.#recordedPrior(prepared);
      this.#verifyBundle(prepared);
      this.#verifyDropIn(prepared);
      await this.#postStartVerifier.verifyActivated("kali:nmap-tcp-connect-service-scan");
      return this.#result(prepared, "activated");
    }
    let prior: RecordedDropInPrior;
    if (initialDropIn.kind === "known_v2") {
      this.#prepareKnownV2UpgradeReceipt(prepared, initialDropIn.bytes);
      prior = "known_v2";
    } else {
      if (this.#recordedPrior(prepared) !== "absent") {
        throw new Error("A retained known-v2 receipt conflicts with an absent live drop-in");
      }
      prior = "absent";
    }

    let stopped = false;
    let published = false;
    try {
      await this.#service.stop(NMAP_ACTIVATION_SERVICE_UNIT);
      stopped = true;
      assertServiceIdentity(await this.#service.identity(), "inactive");
      assertNoActiveWork(this.#readActiveWork());
      try {
        this.#publishDropIn(prepared, prior);
        published = true;
      } catch (publishError) {
        // `rename(2)` may have succeeded before a later directory fsync
        // failure. Re-classify without trusting the thrown operation so the
        // recovery path still restores the exact recorded prior.
        try { published = this.#dropInState(prepared).kind === "v3"; }
        catch { published = false; }
        throw publishError;
      }
      await this.#service.daemonReload();
      await this.#service.start(NMAP_ACTIVATION_SERVICE_UNIT);
      stopped = false;
      assertServiceIdentity(await this.#service.identity(), "active");
      await this.#postStartVerifier.verifyActivated("kali:nmap-tcp-connect-service-scan");
      this.#verifyBundle(prepared);
      this.#verifyDropIn(prepared);
      return this.#result(prepared, "activated");
    } catch (error) {
      if (stopped || published) {
        try {
          if (published) {
            const current = await this.#service.identity();
            if (current.activeState === "active") {
              assertServiceIdentity(current, "active");
              assertNoActiveWork(this.#readActiveWork());
              await this.#service.stop(NMAP_ACTIVATION_SERVICE_UNIT);
              stopped = true;
              assertServiceIdentity(await this.#service.identity(), "inactive");
              assertNoActiveWork(this.#readActiveWork());
            } else {
              assertServiceIdentity(current, "inactive");
              stopped = true;
            }
            this.#restorePriorDropIn(prepared, prior);
          }
          await this.#service.daemonReload();
          await this.#service.start(NMAP_ACTIVATION_SERVICE_UNIT);
          assertServiceIdentity(await this.#service.identity(), "active");
          await this.#postStartVerifier.verifyPriorServiceHealthy();
        } catch (recoveryError) {
          throw new AggregateError(
            [error, recoveryError],
            "Nmap activation failed and prior Ti-Scale health could not be re-established",
          );
        }
      }
      throw error;
    }
    /* c8 ignore stop */
  }

  async verify(): Promise<NmapActivationBundleResult> {
    const prepared = this.#prepare();
    assertBinaryIdentity(
      await this.#nmapInstaller.verify(prepared.installerPath),
      prepared.descriptor,
    );
    this.#verifyBundle(prepared);
    assertServiceIdentity(await this.#service.identity(), "active");
    const state = this.#dropInState(prepared);
    if (state.kind !== "v3") {
      if (state.kind === "known_v2" && this.#recordedPrior(prepared) === "known_v2") {
        this.#verifyUpgradeReceipt(prepared);
      }
      await this.#postStartVerifier.verifyPriorServiceHealthy();
      return this.#result(prepared, "rolled_back");
    }
    this.#recordedPrior(prepared);
    this.#verifyDropIn(prepared);
    await this.#postStartVerifier.verifyActivated("kali:nmap-tcp-connect-service-scan");
    return this.#result(prepared, "activated");
  }

  async rollback(): Promise<NmapActivationBundleResult> {
    if (NMAP_ACTIVATION_MUTATION_DISABLED_ERROR.length > 0) {
      throw new Error(NMAP_ACTIVATION_MUTATION_DISABLED_ERROR);
    }

    /* c8 ignore start -- unreachable retired implementation pending source removal */
    const prepared = this.#prepare();
    assertNoActiveWork(this.#readActiveWork());
    assertServiceIdentity(await this.#service.identity(), "active");
    assertBinaryIdentity(
      await this.#nmapInstaller.verify(prepared.installerPath),
      prepared.descriptor,
    );
    this.#verifyBundle(prepared);
    this.#verifyDropIn(prepared);
    if (this.#dropInState(prepared).kind !== "v3") {
      throw new Error("Explicit rollback requires the exact active v3 drop-in");
    }
    const prior = this.#recordedPrior(prepared);

    const dropInPath = this.#dropInPath(prepared.descriptor);
    const disabledPath = join(
      this.#dropInDirectory,
      `.${prepared.descriptor.dropInName}.${process.pid}.${this.#clock().getTime()}.rollback`,
    );
    let stopped = false;
    let withdrawn = false;
    try {
      await this.#service.stop(NMAP_ACTIVATION_SERVICE_UNIT);
      stopped = true;
      assertServiceIdentity(await this.#service.identity(), "inactive");
      assertNoActiveWork(this.#readActiveWork());
      renameSync(dropInPath, disabledPath);
      withdrawn = true;
      fsyncDirectory(this.#dropInDirectory);
      this.#publishPriorAtEmptyDestination(prepared, prior);
      await this.#service.daemonReload();
      await this.#service.start(NMAP_ACTIVATION_SERVICE_UNIT);
      stopped = false;
      assertServiceIdentity(await this.#service.identity(), "active");
      await this.#postStartVerifier.verifyPriorServiceHealthy();
      unlinkSync(disabledPath);
      fsyncDirectory(this.#dropInDirectory);
      return this.#result(prepared, "rolled_back");
    } catch (error) {
      if (stopped || withdrawn) {
        try {
          if (withdrawn) {
            const current = await this.#service.identity();
            if (current.activeState === "active") {
              assertServiceIdentity(current, "active");
              assertNoActiveWork(this.#readActiveWork());
              await this.#service.stop(NMAP_ACTIVATION_SERVICE_UNIT);
              stopped = true;
              assertServiceIdentity(await this.#service.identity(), "inactive");
              assertNoActiveWork(this.#readActiveWork());
            } else {
              assertServiceIdentity(current, "inactive");
              stopped = true;
            }
            if (!existsSync(disabledPath)) {
              throw new Error("The disabled v3 drop-in is missing during rollback recovery");
            }
            const liveState = this.#dropInState(prepared);
            if ((prior === "absent" && liveState.kind !== "absent")
              || (prior === "known_v2" && liveState.kind !== "known_v2")) {
              throw new Error("The prior drop-in changed during rollback recovery");
            }
            renameSync(disabledPath, dropInPath);
            fsyncDirectory(this.#dropInDirectory);
            this.#verifyDropIn(prepared);
          }
          await this.#service.daemonReload();
          await this.#service.start(NMAP_ACTIVATION_SERVICE_UNIT);
          assertServiceIdentity(await this.#service.identity(), "active");
          await this.#postStartVerifier.verifyActivated("kali:nmap-tcp-connect-service-scan");
        } catch (recoveryError) {
          throw new AggregateError(
            [error, recoveryError],
            "Nmap rollback failed and the prior activated Ti-Scale state could not be re-established",
          );
        }
      }
      throw error;
    }
    /* c8 ignore stop */
  }
}

export function installedFileIdentity(pathValue: string, fileCapabilities: string): NmapBinaryIdentity {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  return Object.freeze({
    path,
    sha256: metadata.isFile() && !metadata.isSymbolicLink() ? sha256(readFileSync(path)) : "",
    uid: metadata.uid,
    gid: metadata.gid,
    mode: metadata.mode & 0o7777,
    fileCapabilities: fileCapabilities.trim() ? fileCapabilities.trim() : "none",
    regularFile: metadata.isFile(),
    symbolicLink: metadata.isSymbolicLink(),
  });
}
