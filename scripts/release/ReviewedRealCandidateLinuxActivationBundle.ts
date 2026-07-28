import { createHash, timingSafeEqual } from "node:crypto";
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
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  type BigIntStats,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import type { SqliteDatabase } from "../../server/db";
import {
  CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
  CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
  candidateLinuxPostExploitSpecificationHash,
  loadTrustedReviewedRealCandidateLinuxProfile,
  parseCandidateLinuxTransportBindingManifest,
  reviewedRealCandidateLinuxOperations,
  type CandidateLinuxTransportBindingManifest,
  type ReviewedRealCandidateLinuxProfile,
} from "../../server/autonomous-runtime";

export const REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_SCHEMA_VERSION =
  "ti-scale.reviewed-real-candidate-linux-activation-bundle.v1" as const;
export const REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_DATABASE_PATH =
  "/var/lib/ti-scale/data/ti-scale.sqlite" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u;
const SAFE_ENVIRONMENT_PATH = /^\/[A-Za-z0-9_./:-]+$/u;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;

export interface ReviewedRealCandidateLinuxActivationPaths {
  readonly trustRoot: string;
  readonly profile: string;
  readonly manifest: string;
  readonly receipt: string;
  readonly adapterEnvironment: string;
  readonly brokerEnvironment: string;
  readonly runtimeEnvironment: string;
  readonly adapterExecutable: string;
  readonly brokerExecutable: string;
  readonly registerExecutable: string;
  readonly adapterSocket: string;
  readonly brokerSocket: string;
  readonly adapterService: string;
  readonly brokerService: string;
  readonly applicationDropIn: string;
}

export const REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS:
ReviewedRealCandidateLinuxActivationPaths = Object.freeze({
  trustRoot: "/etc/ti-scale/candidate-linux-reviewed",
  profile: "/etc/ti-scale/candidate-linux-reviewed/profile.v1.json",
  manifest: "/etc/ti-scale/candidate-linux-reviewed/manifest.v1.json",
  receipt:
    "/etc/ti-scale/candidate-linux-reviewed/installation-receipt.v1.json",
  adapterEnvironment:
    "/etc/ti-scale/reviewed-real-candidate-linux-adapter.env",
  brokerEnvironment:
    "/etc/ti-scale/reviewed-real-candidate-linux-broker.env",
  runtimeEnvironment:
    "/etc/ti-scale/reviewed-real-candidate-linux-runtime.env",
  adapterExecutable:
    "/usr/local/libexec/ti-scale/reviewed-real-candidate-linux-adapter",
  brokerExecutable:
    "/usr/local/libexec/ti-scale/reviewed-real-candidate-linux-broker",
  registerExecutable:
    "/usr/local/libexec/ti-scale/reviewed-real-candidate-linux-register",
  adapterSocket:
    "/run/ti-scale-candidate-linux-reviewed/adapter.sock",
  brokerSocket:
    "/run/ti-scale-candidate-linux-reviewed/broker.sock",
  adapterService:
    "/etc/systemd/system/ti-scale-reviewed-candidate-linux-adapter.service",
  brokerService:
    "/etc/systemd/system/ti-scale-reviewed-candidate-linux-broker.service",
  applicationDropIn:
    "/etc/systemd/system/ti-scale.service.d/81-reviewed-candidate-linux-transport.conf",
});

export interface ReviewedRealCandidateLinuxSourceInput {
  readonly trustRoot: string;
  readonly profilePath: string;
  readonly profileSha256: string;
  readonly adapterExecutablePath: string;
  readonly adapterExecutableSha256: string;
  readonly brokerExecutablePath: string;
  readonly brokerExecutableSha256: string;
  readonly registerExecutablePath: string;
  readonly registerExecutableSha256: string;
  readonly allowedOwnerUids?: readonly number[];
}

export interface ReviewedRealCandidateLinuxSourceAuthority {
  readonly missionId: string;
  readonly runId: string;
  readonly contractId: string;
  readonly contractVersion: number;
  readonly contractHash: string;
  readonly scriptArtifactId: string;
  readonly scriptContentHash: string;
  readonly observerSpecId: string;
  readonly postExploitSpecId: string;
  readonly postExploitSpecSha256: string;
  readonly bindingId: string;
  readonly sourceSpecState: "registered" | "ready_for_registration";
}

export interface ReviewedRealCandidateLinuxActivationReceipt {
  readonly schemaVersion:
    typeof REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_SCHEMA_VERSION;
  readonly bundleVersion: string;
  readonly status: "installed_not_activated";
  readonly backupCreated: false;
  readonly databaseMutated: false;
  readonly systemdReloaded: false;
  readonly servicesStarted: false;
  readonly candidateClass: "reviewed_real_candidate_v1";
  readonly realTargetSupport: true;
  readonly missionExecutionReady: false;
  readonly sourceAuthority: ReviewedRealCandidateLinuxSourceAuthority;
  readonly profile: Readonly<{ path: string; sha256: string }>;
  readonly manifest: Readonly<{ path: string; sha256: string }>;
  readonly adapter: Readonly<{ path: string; sha256: string; socketPath: string }>;
  readonly broker: Readonly<{ path: string; sha256: string; socketPath: string }>;
  readonly register: Readonly<{ path: string; sha256: string }>;
  readonly invocationAuthority: Readonly<{
    readonly exactTarget: "current_canonical_action_only";
    readonly run: "current_derived_spec_only";
    readonly contract: "current_confirmed_hash_bound_contract_only";
    readonly attackAttempt: "succeeded_with_verified_outcome_evidence_only";
    readonly cancellation: "abort_signal_and_lease_fence_required";
  }>;
}

export interface PreparedReviewedRealCandidateLinuxActivation {
  readonly profile: ReviewedRealCandidateLinuxProfile;
  readonly manifest: CandidateLinuxTransportBindingManifest;
  readonly manifestSha256: string;
  readonly receipt: ReviewedRealCandidateLinuxActivationReceipt;
  readonly files: readonly Readonly<{
    readonly path: string;
    readonly bytes: Buffer;
    readonly mode: number;
    readonly gid: number;
  }>[];
}

export interface ReviewedRealCandidateLinuxActivationInput {
  readonly bundleVersion: string;
  readonly database: SqliteDatabase;
  readonly databasePath: string;
  readonly serviceGid: number;
  readonly source: ReviewedRealCandidateLinuxSourceInput;
  readonly paths?: ReviewedRealCandidateLinuxActivationPaths;
  readonly installedOwnerUid?: number;
}

function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function hashBytes(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function absolutePath(value: string, label: string): string {
  if (
    !value
    || !isAbsolute(value)
    || value !== value.trim()
    || value.length > 4_096
    || !SAFE_ENVIRONMENT_PATH.test(value)
  ) {
    throw new Error(`${label} must be a safe absolute path`);
  }
  return resolve(value);
}

function owners(values: readonly number[] | undefined): ReadonlySet<number> {
  const current = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const normalized = values ?? [0, current];
  if (
    normalized.length < 1
    || normalized.length > 4
    || normalized.some((value) =>
      !Number.isSafeInteger(value) || value < 0 || ![0, current].includes(value))
  ) {
    throw new Error("Source owners must be root or the current isolated UID");
  }
  return new Set(normalized);
}

function inside(root: string, path: string): boolean {
  const child = relative(root, path);
  return child !== ""
    && !isAbsolute(child)
    && child !== ".."
    && !child.startsWith(`..${sep}`);
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function assertTrustedSourcePath(
  trustRootValue: string,
  sourcePathValue: string,
  allowedOwners: ReadonlySet<number>,
  executable: boolean,
): { readonly path: string; readonly metadata: BigIntStats } {
  const trustRoot = absolutePath(trustRootValue, "Source trust root");
  const sourcePath = absolutePath(sourcePathValue, "Reviewed source path");
  if (!inside(trustRoot, sourcePath)) {
    throw new Error("Reviewed source path must remain below its trust root");
  }
  const rootMetadata = lstatSync(trustRoot, { bigint: true });
  if (
    rootMetadata.isSymbolicLink()
    || !rootMetadata.isDirectory()
    || !allowedOwners.has(Number(rootMetadata.uid))
    || (Number(rootMetadata.mode) & 0o022) !== 0
    || realpathSync(trustRoot) !== trustRoot
  ) {
    throw new Error("Source trust root is not owner-controlled");
  }
  let cursor = trustRoot;
  const segments = relative(trustRoot, sourcePath).split(sep).filter(Boolean);
  let finalMetadata: BigIntStats | undefined;
  for (const [index, segment] of segments.entries()) {
    cursor = resolve(cursor, segment);
    const metadata = lstatSync(cursor, { bigint: true });
    const final = index === segments.length - 1;
    if (
      metadata.isSymbolicLink()
      || (final ? !metadata.isFile() : !metadata.isDirectory())
      || !allowedOwners.has(Number(metadata.uid))
      || (Number(metadata.mode) & 0o022) !== 0
      || (
        final
        && (
          (Number(metadata.mode) & 0o7000) !== 0
          || (executable && (Number(metadata.mode) & 0o111) === 0)
          || (!executable && (Number(metadata.mode) & 0o111) !== 0)
        )
      )
    ) {
      throw new Error("Reviewed source path is not owner-controlled");
    }
    if (final) finalMetadata = metadata;
  }
  if (!finalMetadata) throw new Error("Reviewed source file is missing");
  return Object.freeze({ path: sourcePath, metadata: finalMetadata });
}

function readPinnedSource(
  source: ReviewedRealCandidateLinuxSourceInput,
  path: string,
  expectedSha256: string,
  executable: boolean,
): Buffer {
  if (!SHA256.test(expectedSha256)) {
    throw new Error("Reviewed source SHA-256 must be lowercase");
  }
  const allowedOwners = owners(source.allowedOwnerUids);
  const trusted = assertTrustedSourcePath(
    source.trustRoot,
    path,
    allowedOwners,
    executable,
  );
  const descriptor = openSync(trusted.path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!sameFile(before, trusted.metadata)) {
      throw new Error("Reviewed source identity changed before read");
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const actual = hashBytes(bytes);
    if (
      !sameFile(before, after)
      || bytes.byteLength !== Number(after.size)
      || !timingSafeEqual(
        Buffer.from(actual, "hex"),
        Buffer.from(expectedSha256, "hex"),
      )
    ) {
      throw new Error("Reviewed source changed or failed SHA-256 verification");
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function inspectSourceAuthority(
  database: SqliteDatabase,
  profile: ReviewedRealCandidateLinuxProfile,
): ReviewedRealCandidateLinuxSourceAuthority {
  const row = database.prepare(`
    SELECT script.id AS script_id, script.content_hash AS script_hash,
      script.validation_state AS script_state,
      script.mission_id AS mission_id, script.run_id AS run_id,
      observer.id AS observer_id,
      observer.script_content_hash AS observer_script_hash,
      observer.status AS observer_status,
      run.contract_id AS contract_id,
      run.contract_version_bound AS contract_version,
      run.contract_hash_bound AS contract_hash
    FROM script_artifacts script
    JOIN exploit_outcome_observer_specs observer
      ON observer.id = ?
      AND observer.script_artifact_id = script.id
    JOIN runs run
      ON run.id = script.run_id
      AND run.mission_id = script.mission_id
      AND run.journey = 'autonomous'
      AND run.control_plane = 'ti_scale'
    JOIN mission_contracts contract
      ON contract.id = run.contract_id
      AND contract.mission_id = run.mission_id
      AND contract.version = run.contract_version_bound
      AND contract.contract_hash = run.contract_hash_bound
      AND contract.state = 'confirmed'
    JOIN missions mission
      ON mission.id = script.mission_id
      AND mission.authorization_status = 'verified'
      AND mission.control_plane = 'ti_scale'
    WHERE script.id = ?
    LIMIT 1
  `).get(
    profile.postExploitSpec.exploitOutcomeObserverSpecId,
    profile.postExploitSpec.scriptArtifactId,
  ) as Readonly<Record<string, string | number | null>> | undefined;
  if (
    !row
    || row.script_state !== "approved"
    || row.observer_status !== "active"
    || row.script_hash !== row.observer_script_hash
    || typeof row.contract_id !== "string"
    || !Number.isSafeInteger(row.contract_version)
    || Number(row.contract_version) < 1
    || typeof row.contract_hash !== "string"
    || !SHA256.test(row.contract_hash)
  ) {
    throw new Error(
      "Profile ScriptArtifact, observer, autonomous run, or confirmed contract identity is not current",
    );
  }
  const expectedSpecSha256 = candidateLinuxPostExploitSpecificationHash({
    exploitOutcomeObserverSpecId:
      profile.postExploitSpec.exploitOutcomeObserverSpecId,
    scriptArtifactId: profile.postExploitSpec.scriptArtifactId,
    scriptContentHash: String(row.script_hash),
    transportType: "candidate_runtime_session_v1",
    transportBindingId: profile.bindingId,
    transportOrigin: null,
    expectedPrincipal: profile.postExploitSpec.expectedPrincipal,
    expectedUid: profile.postExploitSpec.expectedUid,
    declaredUserFlagPath: profile.postExploitSpec.declaredUserFlagPath,
  });
  if (expectedSpecSha256 !== profile.postExploitSpec.expectedSha256) {
    throw new Error(
      "Profile post-exploit spec hash does not recompute from the approved database identities",
    );
  }
  const registered = database.prepare(`
    SELECT id, exploit_outcome_observer_spec_id, script_artifact_id,
      transport_type, transport_binding_id, transport_origin,
      expected_principal, expected_uid, declared_user_flag_path,
      declared_root_flag_path, spec_hash, status
    FROM candidate_linux_post_exploit_specs
    WHERE id = ?
    LIMIT 1
  `).get(profile.postExploitSpec.id) as
    | Readonly<Record<string, string | number | null>>
    | undefined;
  if (
    registered
    && (
      registered.exploit_outcome_observer_spec_id
        !== profile.postExploitSpec.exploitOutcomeObserverSpecId
      || registered.script_artifact_id
        !== profile.postExploitSpec.scriptArtifactId
      || registered.transport_type !== "candidate_runtime_session_v1"
      || registered.transport_binding_id !== profile.bindingId
      || registered.transport_origin !== null
      || registered.expected_principal
        !== profile.postExploitSpec.expectedPrincipal
      || registered.expected_uid !== profile.postExploitSpec.expectedUid
      || registered.declared_user_flag_path
        !== profile.postExploitSpec.declaredUserFlagPath
      || registered.declared_root_flag_path !== "/root/root.txt"
      || registered.spec_hash !== expectedSpecSha256
      || registered.status !== "active"
    )
  ) {
    throw new Error(
      "Existing post-exploit spec disagrees with the reviewed profile",
    );
  }
  return Object.freeze({
    missionId: String(row.mission_id),
    runId: String(row.run_id),
    contractId: String(row.contract_id),
    contractVersion: Number(row.contract_version),
    contractHash: String(row.contract_hash),
    scriptArtifactId: profile.postExploitSpec.scriptArtifactId,
    scriptContentHash: String(row.script_hash),
    observerSpecId:
      profile.postExploitSpec.exploitOutcomeObserverSpecId,
    postExploitSpecId: profile.postExploitSpec.id,
    postExploitSpecSha256: expectedSpecSha256,
    bindingId: profile.bindingId,
    sourceSpecState: registered ? "registered" : "ready_for_registration",
  });
}

function assertLayout(
  paths: ReviewedRealCandidateLinuxActivationPaths,
  profile: ReviewedRealCandidateLinuxProfile,
  serviceGid: number,
  databasePath: string,
): void {
  for (const [name, path] of Object.entries(paths)) {
    absolutePath(path, `Installation ${name}`);
  }
  absolutePath(databasePath, "Database path");
  if (!Number.isSafeInteger(serviceGid) || serviceGid < 1) {
    throw new Error("Ti-Scale service GID must be a positive integer");
  }
  if (
    profile.adapter.executablePath !== resolve(paths.adapterExecutable)
    || profile.adapter.socketPath !== resolve(paths.adapterSocket)
    || profile.adapter.socketGid !== serviceGid
  ) {
    throw new Error(
      "Reviewed profile does not pin the exact installed adapter path, socket, and Ti-Scale group",
    );
  }
}

export function reviewedRealCandidateLinuxSystemdFiles(
  paths: ReviewedRealCandidateLinuxActivationPaths =
    REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
): Readonly<{
  adapterService: string;
  brokerService: string;
  applicationDropIn: string;
}> {
  const adapterService = [
    "[Unit]",
    "Description=Ti-Scale reviewed real-candidate Linux typed adapter",
    "After=network-online.target",
    "Wants=network-online.target",
    "Before=ti-scale-reviewed-candidate-linux-broker.service",
    `ConditionPathExists=${paths.adapterEnvironment}`,
    "",
    "[Service]",
    "Type=simple",
    "User=ti-scale",
    "Group=ti-scale",
    `EnvironmentFile=${paths.adapterEnvironment}`,
    `ExecStart=${paths.adapterExecutable}`,
    "Restart=on-failure",
    "RestartSec=2s",
    "TimeoutStartSec=15s",
    "TimeoutStopSec=15s",
    "RuntimeDirectory=ti-scale-candidate-linux-reviewed",
    "RuntimeDirectoryMode=0750",
    "StateDirectory=ti-scale-candidate-linux-reviewed",
    "StateDirectoryMode=0700",
    "UMask=0007",
    "NoNewPrivileges=yes",
    "PrivateDevices=yes",
    "PrivateTmp=yes",
    "ProtectClock=yes",
    "ProtectControlGroups=yes",
    "ProtectHome=yes",
    "ProtectHostname=yes",
    "ProtectKernelLogs=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelTunables=yes",
    "ProtectSystem=strict",
    "ReadWritePaths=/run/ti-scale-candidate-linux-reviewed /var/lib/ti-scale-candidate-linux-reviewed",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=EPERM",
    "TasksMax=64",
    "MemoryMax=512M",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
  const brokerService = [
    "[Unit]",
    "Description=Ti-Scale reviewed real-candidate Linux typed transport broker",
    "After=local-fs.target ti-scale-reviewed-candidate-linux-adapter.service",
    "Requires=ti-scale-reviewed-candidate-linux-adapter.service",
    "Before=ti-scale.service",
    `ConditionPathExists=${paths.brokerEnvironment}`,
    "",
    "[Service]",
    "Type=simple",
    "User=ti-scale",
    "Group=ti-scale",
    `EnvironmentFile=${paths.brokerEnvironment}`,
    `ExecStart=${paths.brokerExecutable}`,
    "Restart=on-failure",
    "RestartSec=2s",
    "TimeoutStartSec=15s",
    "TimeoutStopSec=10s",
    "RuntimeDirectory=ti-scale-candidate-linux-reviewed",
    "RuntimeDirectoryMode=0750",
    "StateDirectory=ti-scale-candidate-linux-reviewed",
    "StateDirectoryMode=0700",
    "UMask=0007",
    "NoNewPrivileges=yes",
    "PrivateDevices=yes",
    "PrivateTmp=yes",
    "ProtectClock=yes",
    "ProtectControlGroups=yes",
    "ProtectHome=yes",
    "ProtectHostname=yes",
    "ProtectKernelLogs=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelTunables=yes",
    "ProtectSystem=strict",
    "ReadOnlyPaths=/var/lib/ti-scale/data",
    "ReadWritePaths=/run/ti-scale-candidate-linux-reviewed",
    "RestrictAddressFamilies=AF_UNIX",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=EPERM",
    "TasksMax=32",
    "MemoryMax=256M",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
  const applicationDropIn = [
    "[Unit]",
    "Wants=ti-scale-reviewed-candidate-linux-broker.service",
    "After=ti-scale-reviewed-candidate-linux-broker.service",
    "",
    "[Service]",
    `EnvironmentFile=${paths.runtimeEnvironment}`,
    "",
  ].join("\n");
  return Object.freeze({
    adapterService,
    brokerService,
    applicationDropIn,
  });
}

export function prepareReviewedRealCandidateLinuxActivation(
  input: ReviewedRealCandidateLinuxActivationInput,
): PreparedReviewedRealCandidateLinuxActivation {
  if (!VERSION.test(input.bundleVersion)) {
    throw new Error("Bundle version must be a stable identifier");
  }
  const paths = input.paths
    ?? REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS;
  const allowedOwnerUids = [...owners(input.source.allowedOwnerUids)];
  const loadedProfile = loadTrustedReviewedRealCandidateLinuxProfile({
    path: absolutePath(input.source.profilePath, "Reviewed profile path"),
    trustRoot: absolutePath(input.source.trustRoot, "Source trust root"),
    expectedSha256: input.source.profileSha256,
    allowedOwnerUids,
    maximumBytes: 64 * 1_024,
  });
  const adapterBytes = readPinnedSource(
    input.source,
    input.source.adapterExecutablePath,
    input.source.adapterExecutableSha256,
    true,
  );
  const brokerBytes = readPinnedSource(
    input.source,
    input.source.brokerExecutablePath,
    input.source.brokerExecutableSha256,
    true,
  );
  const registerBytes = readPinnedSource(
    input.source,
    input.source.registerExecutablePath,
    input.source.registerExecutableSha256,
    true,
  );
  if (
    input.source.adapterExecutableSha256
      !== loadedProfile.value.adapter.executableSha256
  ) {
    throw new Error(
      "Reviewed adapter executable hash differs from the profile pin",
    );
  }
  assertLayout(
    paths,
    loadedProfile.value,
    input.serviceGid,
    input.databasePath,
  );
  const sourceAuthority = inspectSourceAuthority(
    input.database,
    loadedProfile.value,
  );
  const manifest = parseCandidateLinuxTransportBindingManifest({
    schemaVersion:
      CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
    bundleVersion: input.bundleVersion,
    broker: {
      executablePath: paths.brokerExecutable,
      executableSha256: input.source.brokerExecutableSha256,
      socketPath: paths.brokerSocket,
      socketGid: input.serviceGid,
      protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
    },
    boundary: {
      typedOperationsOnly: true,
      genericCommand: false,
      shell: false,
      argv: false,
      payload: false,
      credentials: false,
      exactTargetFromCanonicalAction: true,
      succeededAttackAttemptRequired: true,
      publicProvider: false,
    },
    bindings: [{
      bindingId: loadedProfile.value.bindingId,
      postExploitSpecId: loadedProfile.value.postExploitSpec.id,
      postExploitSpecSha256:
        loadedProfile.value.postExploitSpec.expectedSha256,
      candidateClass: "reviewed_real_candidate_v1",
      handlerProfilePath: paths.profile,
      handlerProfileSha256: loadedProfile.receipt.sourceSha256,
      realTargetSupport: true,
      operations: reviewedRealCandidateLinuxOperations(),
    }],
  });
  const manifestBytes = canonicalBytes(manifest);
  const manifestSha256 = hashBytes(manifestBytes);
  const receipt: ReviewedRealCandidateLinuxActivationReceipt =
    Object.freeze({
      schemaVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_SCHEMA_VERSION,
      bundleVersion: input.bundleVersion,
      status: "installed_not_activated",
      backupCreated: false,
      databaseMutated: false,
      systemdReloaded: false,
      servicesStarted: false,
      candidateClass: "reviewed_real_candidate_v1",
      realTargetSupport: true,
      missionExecutionReady: false,
      sourceAuthority,
      profile: Object.freeze({
        path: paths.profile,
        sha256: loadedProfile.receipt.sourceSha256,
      }),
      manifest: Object.freeze({
        path: paths.manifest,
        sha256: manifestSha256,
      }),
      adapter: Object.freeze({
        path: paths.adapterExecutable,
        sha256: input.source.adapterExecutableSha256,
        socketPath: paths.adapterSocket,
      }),
      broker: Object.freeze({
        path: paths.brokerExecutable,
        sha256: input.source.brokerExecutableSha256,
        socketPath: paths.brokerSocket,
      }),
      register: Object.freeze({
        path: paths.registerExecutable,
        sha256: input.source.registerExecutableSha256,
      }),
      invocationAuthority: Object.freeze({
        exactTarget: "current_canonical_action_only",
        run: "current_derived_spec_only",
        contract: "current_confirmed_hash_bound_contract_only",
        attackAttempt:
          "succeeded_with_verified_outcome_evidence_only",
        cancellation: "abort_signal_and_lease_fence_required",
      }),
    });
  const systemd = reviewedRealCandidateLinuxSystemdFiles(paths);
  const databasePath = absolutePath(input.databasePath, "Database path");
  const profileBytes = readPinnedSource(
    input.source,
    input.source.profilePath,
    input.source.profileSha256,
    false,
  );
  const files = Object.freeze([
    {
      path: paths.adapterExecutable,
      bytes: adapterBytes,
      mode: 0o550,
      gid: input.serviceGid,
    },
    {
      path: paths.brokerExecutable,
      bytes: brokerBytes,
      mode: 0o550,
      gid: input.serviceGid,
    },
    {
      path: paths.registerExecutable,
      bytes: registerBytes,
      mode: 0o550,
      gid: input.serviceGid,
    },
    {
      path: paths.profile,
      bytes: profileBytes,
      mode: 0o440,
      gid: input.serviceGid,
    },
    {
      path: paths.manifest,
      bytes: manifestBytes,
      mode: 0o440,
      gid: input.serviceGid,
    },
    {
      path: paths.receipt,
      bytes: canonicalBytes(receipt),
      mode: 0o440,
      gid: input.serviceGid,
    },
    {
      path: paths.adapterEnvironment,
      bytes: Buffer.from([
        `TI_SCALE_CANDIDATE_LINUX_TRUST_ROOT=${paths.trustRoot}`,
        `TI_SCALE_CANDIDATE_LINUX_PROFILE_PATH=${paths.profile}`,
        `TI_SCALE_CANDIDATE_LINUX_PROFILE_SHA256=${loadedProfile.receipt.sourceSha256}`,
        "",
      ].join("\n")),
      mode: 0o440,
      gid: input.serviceGid,
    },
    {
      path: paths.brokerEnvironment,
      bytes: Buffer.from([
        `TI_SCALE_CANDIDATE_LINUX_TRUST_ROOT=${paths.trustRoot}`,
        `TI_SCALE_CANDIDATE_LINUX_MANIFEST_PATH=${paths.manifest}`,
        `TI_SCALE_CANDIDATE_LINUX_MANIFEST_SHA256=${manifestSha256}`,
        `TI_SCALE_DATABASE_PATH=${databasePath}`,
        "",
      ].join("\n")),
      mode: 0o440,
      gid: input.serviceGid,
    },
    {
      path: paths.runtimeEnvironment,
      bytes: Buffer.from([
        `TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_TRUST_ROOT=${paths.trustRoot}`,
        `TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_MANIFEST_PATH=${paths.manifest}`,
        `TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_MANIFEST_SHA256=${manifestSha256}`,
        "",
      ].join("\n")),
      mode: 0o440,
      gid: 0,
    },
    {
      path: paths.adapterService,
      bytes: Buffer.from(systemd.adapterService),
      mode: 0o644,
      gid: 0,
    },
    {
      path: paths.brokerService,
      bytes: Buffer.from(systemd.brokerService),
      mode: 0o644,
      gid: 0,
    },
    {
      path: paths.applicationDropIn,
      bytes: Buffer.from(systemd.applicationDropIn),
      mode: 0o644,
      gid: 0,
    },
  ].map((file) => Object.freeze(file)));
  return Object.freeze({
    profile: loadedProfile.value,
    manifest,
    manifestSha256,
    receipt,
    files,
  });
}

function assertDestinationParent(path: string, ownerUid: number): void {
  const parent = dirname(path);
  const metadata = lstatSync(parent);
  if (
    metadata.isSymbolicLink()
    || !metadata.isDirectory()
    || metadata.uid !== ownerUid
    || (metadata.mode & 0o022) !== 0
    || realpathSync(parent) !== parent
  ) {
    throw new Error(`Installation parent is not owner-controlled: ${parent}`);
  }
}

function verifyInstalledFile(
  file: PreparedReviewedRealCandidateLinuxActivation["files"][number],
  ownerUid: number,
): void {
  const metadata = lstatSync(file.path, { bigint: true });
  const descriptor = openSync(file.path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (
      metadata.isSymbolicLink()
      || !metadata.isFile()
      || !sameFile(metadata, opened)
      || !sameFile(opened, after)
      || Number(after.uid) !== ownerUid
      || Number(after.gid) !== file.gid
      || (Number(after.mode) & 0o7777) !== file.mode
      || bytes.byteLength !== Number(after.size)
      || !timingSafeEqual(
        Buffer.from(hashBytes(bytes), "hex"),
        Buffer.from(hashBytes(file.bytes), "hex"),
      )
    ) {
      throw new Error(
        `Installed activation file identity drifted: ${file.path}`,
      );
    }
  } finally {
    closeSync(descriptor);
  }
}

function syncInstalledFile(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function syncDirectory(path: string): void {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW,
  );
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

/**
 * Forward-only file publication for one separately reviewed candidate.
 *
 * It performs no database mutation, systemd reload, enable, start, restart,
 * socket call, target contact, or backup. Existing destinations are an error;
 * a failed invocation removes only files and the empty trust root created by
 * that same invocation.
 */
export class ReviewedRealCandidateLinuxActivationInstaller {
  constructor(private readonly input: ReviewedRealCandidateLinuxActivationInput) {}

  prepare(): PreparedReviewedRealCandidateLinuxActivation {
    return prepareReviewedRealCandidateLinuxActivation(this.input);
  }

  install(): ReviewedRealCandidateLinuxActivationReceipt {
    const ownerUid = this.input.installedOwnerUid ?? 0;
    const prepared = this.prepare();
    const paths = this.input.paths
      ?? REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS;
    if (existsSync(paths.trustRoot)) {
      throw new Error(
        "Reviewed real-candidate trust root already exists; forward-only installation refuses replacement",
      );
    }
    for (const file of prepared.files) {
      if (existsSync(file.path)) {
        throw new Error(
          `Reviewed real-candidate destination already exists: ${file.path}`,
        );
      }
      if (dirname(file.path) !== paths.trustRoot) {
        assertDestinationParent(file.path, ownerUid);
      }
    }
    const created: string[] = [];
    let trustRootCreated = false;
    try {
      assertDestinationParent(paths.trustRoot, ownerUid);
      mkdirSync(paths.trustRoot, { mode: 0o750 });
      trustRootCreated = true;
      chownSync(paths.trustRoot, ownerUid, this.input.serviceGid);
      chmodSync(paths.trustRoot, 0o750);
      for (const file of prepared.files) {
        writeFileSync(file.path, file.bytes, {
          flag: "wx",
          mode: file.mode,
        });
        created.push(file.path);
        chownSync(file.path, ownerUid, file.gid);
        chmodSync(file.path, file.mode);
        syncInstalledFile(file.path);
      }
      for (const file of prepared.files) {
        verifyInstalledFile(file, ownerUid);
      }
      for (const directory of new Set([
        paths.trustRoot,
        ...prepared.files.map(({ path }) => dirname(path)),
      ])) {
        syncDirectory(directory);
      }
      return prepared.receipt;
    } catch (error) {
      for (const path of created.reverse()) {
        try { unlinkSync(path); } catch { /* remove only this invocation */ }
      }
      if (trustRootCreated) {
        try { rmSync(paths.trustRoot, { recursive: false }); } catch {
          /* leave fail-closed partial ownership evidence */
        }
      }
      throw error;
    }
  }

  verifyInstalled(): ReviewedRealCandidateLinuxActivationReceipt {
    const ownerUid = this.input.installedOwnerUid ?? 0;
    const prepared = this.prepare();
    for (const file of prepared.files) {
      verifyInstalledFile(file, ownerUid);
    }
    return prepared.receipt;
  }
}
