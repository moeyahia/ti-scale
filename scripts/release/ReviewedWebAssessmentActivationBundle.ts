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
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const REVIEWED_WEB_ASSESSMENT_ACTIVATION_SCHEMA_VERSION =
  "ti-scale.reviewed-web-assessment-activation-bundle.v1" as const;
export const REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION =
  "reviewed-web-assessment-2026.07.20-v1" as const;
export const REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT = "ti-scale.service" as const;
export const REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME =
  "70-reviewed-web-assessment.conf" as const;
export const REVIEWED_WEB_ASSESSMENT_DESCRIPTOR_RELATIVE_PATH =
  "deployment/runtime-config/reviewed-web-assessment-activation-bundle.v1.json" as const;
export const REVIEWED_WEB_ASSESSMENT_DESCRIPTOR_SHA256 =
  "1475b256854a9953c330c1ed1ddcecaa9e33ff66243200ee02199113d49699c4" as const;

const ENVIRONMENT_SOURCE =
  "deployment/runtime-config/reviewed-web-assessment-activation-environment.v1.conf" as const;
const ENVIRONMENT_INSTALL_NAME = "activation-environment.v1.conf" as const;
const ENVIRONMENT_SHA256 =
  "fb6a67dab85ae66c7befe0c9e045aba33e830b5f57d25b1533d014454bef4a5e" as const;
const DROP_IN_SOURCE =
  "deployment/systemd/ti-scale.service.d/70-reviewed-web-assessment.conf" as const;
const DROP_IN_SHA256 =
  "5e0b819fb487b6b3345b8cd36748cccc670c0f3dada139faeb01367f790f0aa6" as const;
const ROLLBACK_RECEIPT_NAME = "rollback-receipt.v1.json" as const;
const INSTALLED_DESCRIPTOR_NAME = "activation-bundle.v1.json" as const;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const SHA256 = /^[a-f0-9]{64}$/u;

const REQUIRED_ACTIVATION_STEPS = Object.freeze([
  "systemctl daemon-reload",
  "systemctl restart ti-scale.service",
  "authenticated capability readiness verification",
] as const);

export interface ReviewedWebAssessmentActivationBundleDescriptor {
  readonly schemaVersion: typeof REVIEWED_WEB_ASSESSMENT_ACTIVATION_SCHEMA_VERSION;
  readonly bundleVersion: typeof REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION;
  readonly serviceUnit: typeof REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT;
  readonly installRoot: "/etc/ti-scale/runtime/bundles";
  readonly dropInDirectory: "/etc/systemd/system/ti-scale.service.d";
  readonly dropInName: typeof REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME;
  readonly environment: Readonly<{
    readonly sourcePath: typeof ENVIRONMENT_SOURCE;
    readonly installName: typeof ENVIRONMENT_INSTALL_NAME;
    readonly sha256: typeof ENVIRONMENT_SHA256;
    readonly sourceMode: 0o644;
    readonly installMode: 0o440;
  }>;
  readonly dropIn: Readonly<{
    readonly sourcePath: typeof DROP_IN_SOURCE;
    readonly sha256: typeof DROP_IN_SHA256;
    readonly sourceMode: 0o644;
    readonly installMode: 0o644;
  }>;
  readonly rollbackReceiptName: typeof ROLLBACK_RECEIPT_NAME;
  readonly activationRequires: typeof REQUIRED_ACTIVATION_STEPS;
}

interface PreparedBundle {
  readonly descriptor: ReviewedWebAssessmentActivationBundleDescriptor;
  readonly descriptorBytes: Buffer;
  readonly environmentBytes: Buffer;
  readonly dropInBytes: Buffer;
}

interface RollbackReceipt {
  readonly schemaVersion: "ti-scale.reviewed-web-assessment-rollback-receipt.v1";
  readonly bundleVersion: typeof REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION;
  readonly serviceUnit: typeof REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT;
  readonly installedAt: string;
  readonly environmentSha256: typeof ENVIRONMENT_SHA256;
  readonly dropInSha256: typeof DROP_IN_SHA256;
  readonly priorDropIn: Readonly<{
    readonly state: "absent" | "present";
    readonly sha256: string | null;
    readonly bytesBase64: string | null;
  }>;
  readonly serviceRestarted: false;
}

export interface ReviewedWebAssessmentActivationInstallerOptions {
  readonly sourceRoot: string;
  readonly sourceOwnerUid?: number;
  readonly installedOwnerUid?: number;
  readonly installedGroupGid: number;
  readonly bundleInstallRoot?: string;
  readonly dropInDirectory?: string;
  readonly clock?: () => Date;
}

export interface ReviewedWebAssessmentActivationResult {
  readonly bundleVersion: typeof REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION;
  readonly status: "installed_pending_restart" | "verified_pending_restart" | "rolled_back_pending_restart";
  readonly serviceUnit: typeof REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT;
  readonly bundleDirectory: string;
  readonly dropInPath: string;
  readonly environmentSha256: typeof ENVIRONMENT_SHA256;
  readonly dropInSha256: typeof DROP_IN_SHA256;
  readonly serviceRestarted: false;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${label} must contain exactly ${canonical.join(", ")}`);
  }
}

function parseDescriptor(value: unknown): ReviewedWebAssessmentActivationBundleDescriptor {
  const descriptor = object(value, "Reviewed web-assessment activation descriptor");
  exactKeys(descriptor, [
    "activationRequires", "bundleVersion", "dropIn", "dropInDirectory", "dropInName",
    "environment", "installRoot", "rollbackReceiptName", "schemaVersion", "serviceUnit",
  ], "Reviewed web-assessment activation descriptor");
  const environment = object(descriptor.environment, "Activation environment descriptor");
  const dropIn = object(descriptor.dropIn, "Activation drop-in descriptor");
  const activationRequires = descriptor.activationRequires;
  exactKeys(environment, [
    "installMode", "installName", "sha256", "sourceMode", "sourcePath",
  ], "Activation environment descriptor");
  exactKeys(dropIn, [
    "installMode", "sha256", "sourceMode", "sourcePath",
  ], "Activation drop-in descriptor");
  if (descriptor.schemaVersion !== REVIEWED_WEB_ASSESSMENT_ACTIVATION_SCHEMA_VERSION
    || descriptor.bundleVersion !== REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION
    || descriptor.serviceUnit !== REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT
    || descriptor.installRoot !== "/etc/ti-scale/runtime/bundles"
    || descriptor.dropInDirectory !== "/etc/systemd/system/ti-scale.service.d"
    || descriptor.dropInName !== REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME
    || descriptor.rollbackReceiptName !== ROLLBACK_RECEIPT_NAME
    || environment.sourcePath !== ENVIRONMENT_SOURCE
    || environment.installName !== ENVIRONMENT_INSTALL_NAME
    || environment.sha256 !== ENVIRONMENT_SHA256
    || environment.sourceMode !== 0o644
    || environment.installMode !== 0o440
    || dropIn.sourcePath !== DROP_IN_SOURCE
    || dropIn.sha256 !== DROP_IN_SHA256
    || dropIn.sourceMode !== 0o644
    || dropIn.installMode !== 0o644
    || !Array.isArray(activationRequires)
    || activationRequires.length !== REQUIRED_ACTIVATION_STEPS.length
    || REQUIRED_ACTIVATION_STEPS.some((step, index) => activationRequires[index] !== step)) {
    throw new Error("Reviewed web-assessment activation identity or Ti-Scale service boundary is invalid");
  }
  return Object.freeze({
    schemaVersion: REVIEWED_WEB_ASSESSMENT_ACTIVATION_SCHEMA_VERSION,
    bundleVersion: REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION,
    serviceUnit: REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT,
    installRoot: "/etc/ti-scale/runtime/bundles",
    dropInDirectory: "/etc/systemd/system/ti-scale.service.d",
    dropInName: REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME,
    environment: Object.freeze({
      sourcePath: ENVIRONMENT_SOURCE,
      installName: ENVIRONMENT_INSTALL_NAME,
      sha256: ENVIRONMENT_SHA256,
      sourceMode: 0o644,
      installMode: 0o440,
    }),
    dropIn: Object.freeze({
      sourcePath: DROP_IN_SOURCE,
      sha256: DROP_IN_SHA256,
      sourceMode: 0o644,
      installMode: 0o644,
    }),
    rollbackReceiptName: ROLLBACK_RECEIPT_NAME,
    activationRequires: REQUIRED_ACTIVATION_STEPS,
  });
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child !== "" && !isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`);
}

function trustedSourceFile(input: Readonly<{
  sourceRoot: string;
  relativePath: string;
  expectedSha256: string;
  expectedMode: number;
  ownerUid: number;
}>): Buffer {
  if (!SHA256.test(input.expectedSha256)) throw new Error("Pinned source SHA-256 is invalid");
  const root = resolve(input.sourceRoot);
  const path = resolve(root, input.relativePath);
  if (!containedBy(root, path)) throw new Error("Pinned activation source escapes its source root");
  const rootMetadata = lstatSync(root);
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()
    || rootMetadata.uid !== input.ownerUid || (rootMetadata.mode & 0o022) !== 0) {
    throw new Error("Activation source root is not an immutable trusted directory");
  }
  let current = root;
  const segments = relative(root, path).split(sep).filter(Boolean);
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment);
    const metadata = lstatSync(current);
    const final = index === segments.length - 1;
    if (metadata.isSymbolicLink() || (final ? !metadata.isFile() : !metadata.isDirectory())
      || metadata.uid !== input.ownerUid || (metadata.mode & 0o022) !== 0
      || (final && (metadata.mode & 0o7777) !== input.expectedMode)) {
      throw new Error(`Activation source identity is unsafe or drifted: ${input.relativePath}`);
    }
  }
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
      || sha256(bytes) !== input.expectedSha256) {
      throw new Error(`Activation source changed or failed SHA-256 verification: ${input.relativePath}`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

export function loadReviewedWebAssessmentActivationBundle(
  sourceRoot: string,
  sourceOwnerUid = 0,
): PreparedBundle {
  const descriptorBytes = trustedSourceFile({
    sourceRoot,
    relativePath: REVIEWED_WEB_ASSESSMENT_DESCRIPTOR_RELATIVE_PATH,
    expectedSha256: REVIEWED_WEB_ASSESSMENT_DESCRIPTOR_SHA256,
    expectedMode: 0o644,
    ownerUid: sourceOwnerUid,
  });
  const descriptor = parseDescriptor(JSON.parse(descriptorBytes.toString("utf8")));
  const environmentBytes = trustedSourceFile({
    sourceRoot,
    relativePath: descriptor.environment.sourcePath,
    expectedSha256: descriptor.environment.sha256,
    expectedMode: descriptor.environment.sourceMode,
    ownerUid: sourceOwnerUid,
  });
  const dropInBytes = trustedSourceFile({
    sourceRoot,
    relativePath: descriptor.dropIn.sourcePath,
    expectedSha256: descriptor.dropIn.sha256,
    expectedMode: descriptor.dropIn.sourceMode,
    ownerUid: sourceOwnerUid,
  });
  if (environmentBytes.toString("utf8") !== "TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED=true\n") {
    throw new Error("Activation environment contains values outside the reviewed web flag");
  }
  const expectedDropIn = [
    "[Service]",
    `EnvironmentFile=${descriptor.installRoot}/${descriptor.bundleVersion}/${descriptor.environment.installName}`,
    "",
  ].join("\n");
  if (dropInBytes.toString("utf8") !== expectedDropIn) {
    throw new Error("Activation drop-in does not target the exact versioned Ti-Scale environment file");
  }
  return Object.freeze({ descriptor, descriptorBytes, environmentBytes, dropInBytes });
}

function assertDestinationDirectory(path: string, uid: number, gid: number, mode: number): void {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || metadata.uid !== uid
    || metadata.gid !== gid || (metadata.mode & 0o7777) !== mode) {
    throw new Error(`Activation destination directory identity is invalid: ${path}`);
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function writeExact(path: string, bytes: Buffer, uid: number, gid: number, mode: number): void {
  writeFileSync(path, bytes, { flag: "wx", mode });
  chownSync(path, uid, gid);
  chmodSync(path, mode);
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function replaceExact(
  path: string,
  bytes: Buffer,
  uid: number,
  gid: number,
  mode: number,
  clock: () => Date,
): void {
  const temporary = join(dirname(path), `.${REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME}.${process.pid}.${clock().getTime()}.tmp`);
  try {
    writeExact(temporary, bytes, uid, gid, mode);
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

function verifyFile(path: string, digest: string, uid: number, gid: number, mode: number): void {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.uid !== uid
    || metadata.gid !== gid || (metadata.mode & 0o7777) !== mode
    || sha256(readFileSync(path)) !== digest) {
    throw new Error(`Installed activation file failed exact identity verification: ${path}`);
  }
}

function readPriorDropIn(path: string, uid: number): RollbackReceipt["priorDropIn"] {
  if (!existsSync(path)) return { state: "absent", sha256: null, bytesBase64: null };
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.uid !== uid
    || (metadata.mode & 0o022) !== 0 || (metadata.mode & 0o7777) !== 0o644) {
    throw new Error("Existing web-assessment drop-in is not a trusted regular 0644 file");
  }
  const bytes = readFileSync(path);
  if (sha256(bytes) === DROP_IN_SHA256) {
    throw new Error("An orphaned reviewed web-assessment drop-in exists without its rollback receipt");
  }
  return { state: "present", sha256: sha256(bytes), bytesBase64: bytes.toString("base64") };
}

function parseRollbackReceipt(bytes: Buffer): RollbackReceipt {
  const value = object(JSON.parse(bytes.toString("utf8")), "Web-assessment rollback receipt");
  exactKeys(value, [
    "bundleVersion", "dropInSha256", "environmentSha256", "installedAt", "priorDropIn",
    "schemaVersion", "serviceRestarted", "serviceUnit",
  ], "Web-assessment rollback receipt");
  const prior = object(value.priorDropIn, "Web-assessment prior drop-in receipt");
  exactKeys(prior, ["bytesBase64", "sha256", "state"], "Web-assessment prior drop-in receipt");
  const installed = Date.parse(String(value.installedAt));
  if (value.schemaVersion !== "ti-scale.reviewed-web-assessment-rollback-receipt.v1"
    || value.bundleVersion !== REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION
    || value.serviceUnit !== REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT
    || value.environmentSha256 !== ENVIRONMENT_SHA256
    || value.dropInSha256 !== DROP_IN_SHA256
    || value.serviceRestarted !== false
    || !Number.isFinite(installed)
    || new Date(installed).toISOString() !== value.installedAt
    || (prior.state !== "absent" && prior.state !== "present")) {
    throw new Error("Web-assessment rollback receipt identity is invalid");
  }
  if (prior.state === "absent") {
    if (prior.sha256 !== null || prior.bytesBase64 !== null) throw new Error("Absent prior drop-in receipt contains bytes");
    return value as unknown as RollbackReceipt;
  }
  if (typeof prior.sha256 !== "string" || !SHA256.test(prior.sha256)
    || typeof prior.bytesBase64 !== "string"
    || sha256(Buffer.from(prior.bytesBase64, "base64")) !== prior.sha256) {
    throw new Error("Prior drop-in rollback payload failed SHA-256 verification");
  }
  return value as unknown as RollbackReceipt;
}

export class ReviewedWebAssessmentActivationInstaller {
  private readonly sourceOwnerUid: number;
  private readonly installedOwnerUid: number;
  private readonly bundleInstallRoot: string;
  private readonly dropInDirectory: string;
  private readonly clock: () => Date;

  constructor(private readonly options: ReviewedWebAssessmentActivationInstallerOptions) {
    this.sourceOwnerUid = options.sourceOwnerUid ?? 0;
    this.installedOwnerUid = options.installedOwnerUid ?? 0;
    this.bundleInstallRoot = resolve(options.bundleInstallRoot ?? "/etc/ti-scale/runtime/bundles");
    this.dropInDirectory = resolve(options.dropInDirectory ?? "/etc/systemd/system/ti-scale.service.d");
    this.clock = options.clock ?? (() => new Date());
    if (!isAbsolute(options.sourceRoot) || resolve(options.sourceRoot) !== options.sourceRoot
      || (options.bundleInstallRoot !== undefined
        && (!isAbsolute(options.bundleInstallRoot)
          || resolve(options.bundleInstallRoot) !== options.bundleInstallRoot))
      || (options.dropInDirectory !== undefined
        && (!isAbsolute(options.dropInDirectory)
          || resolve(options.dropInDirectory) !== options.dropInDirectory))
      || !isAbsolute(this.bundleInstallRoot)
      || !isAbsolute(this.dropInDirectory) || !Number.isSafeInteger(options.installedGroupGid)
      || options.installedGroupGid < 0) {
      throw new Error("Reviewed web-assessment activation paths or service group are invalid");
    }
  }

  private paths() {
    const bundleDirectory = join(this.bundleInstallRoot, REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION);
    return {
      bundleDirectory,
      environmentPath: join(bundleDirectory, ENVIRONMENT_INSTALL_NAME),
      descriptorPath: join(bundleDirectory, INSTALLED_DESCRIPTOR_NAME),
      receiptPath: join(bundleDirectory, ROLLBACK_RECEIPT_NAME),
      dropInPath: join(this.dropInDirectory, REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME),
    };
  }

  private result(status: ReviewedWebAssessmentActivationResult["status"]): ReviewedWebAssessmentActivationResult {
    const paths = this.paths();
    return Object.freeze({
      bundleVersion: REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION,
      status,
      serviceUnit: REVIEWED_WEB_ASSESSMENT_SERVICE_UNIT,
      bundleDirectory: paths.bundleDirectory,
      dropInPath: paths.dropInPath,
      environmentSha256: ENVIRONMENT_SHA256,
      dropInSha256: DROP_IN_SHA256,
      serviceRestarted: false,
    });
  }

  installPendingRestart(): ReviewedWebAssessmentActivationResult {
    const prepared = loadReviewedWebAssessmentActivationBundle(
      this.options.sourceRoot,
      this.sourceOwnerUid,
    );
    const paths = this.paths();
    assertDestinationDirectory(
      this.bundleInstallRoot,
      this.installedOwnerUid,
      this.options.installedGroupGid,
      0o750,
    );
    assertDestinationDirectory(this.dropInDirectory, this.installedOwnerUid, 0, 0o755);
    if (existsSync(paths.bundleDirectory)) return this.verifyPendingRestart();
    const priorDropIn = readPriorDropIn(paths.dropInPath, this.installedOwnerUid);
    mkdirSync(paths.bundleDirectory, { mode: 0o750 });
    chownSync(paths.bundleDirectory, this.installedOwnerUid, this.options.installedGroupGid);
    chmodSync(paths.bundleDirectory, 0o750);
    try {
      writeExact(paths.environmentPath, prepared.environmentBytes, this.installedOwnerUid, this.options.installedGroupGid, 0o440);
      writeExact(paths.descriptorPath, prepared.descriptorBytes, this.installedOwnerUid, this.options.installedGroupGid, 0o440);
      fsyncDirectory(paths.bundleDirectory);
      replaceExact(paths.dropInPath, prepared.dropInBytes, this.installedOwnerUid, 0, 0o644, this.clock);
      this.verifyPendingRestart();
      return this.result("installed_pending_restart");
    } catch (error) {
      if (priorDropIn.state === "absent") rmSync(paths.dropInPath, { force: true });
      else replaceExact(
        paths.dropInPath,
        Buffer.from(priorDropIn.bytesBase64!, "base64"),
        this.installedOwnerUid,
        0,
        0o644,
        this.clock,
      );
      rmSync(paths.bundleDirectory, { recursive: true, force: true });
      throw error;
    }
  }

  verifyPendingRestart(): ReviewedWebAssessmentActivationResult {
    loadReviewedWebAssessmentActivationBundle(this.options.sourceRoot, this.sourceOwnerUid);
    const paths = this.paths();
    assertDestinationDirectory(paths.bundleDirectory, this.installedOwnerUid, this.options.installedGroupGid, 0o750);
    verifyFile(paths.environmentPath, ENVIRONMENT_SHA256, this.installedOwnerUid, this.options.installedGroupGid, 0o440);
    verifyFile(paths.descriptorPath, REVIEWED_WEB_ASSESSMENT_DESCRIPTOR_SHA256, this.installedOwnerUid, this.options.installedGroupGid, 0o440);
    verifyFile(paths.dropInPath, DROP_IN_SHA256, this.installedOwnerUid, 0, 0o644);
    if (existsSync(paths.receiptPath)) {
      throw new Error(
        "Persisted web-assessment rollback receipt is forbidden by the operator no-backup policy",
      );
    }
    return this.result("verified_pending_restart");
  }

  rollbackPendingRestart(): ReviewedWebAssessmentActivationResult {
    throw new Error(
      "Web-assessment rollback is disabled by the operator no-backup policy",
    );
  }
}
