import {
  chmodSync,
  chownSync,
  copyFileSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, resolve } from "node:path";
import {
  createDatabaseConnection,
} from "../server/db";
import {
  createDisposableCandidateLinuxTransportBundle,
} from "./release/DisposableCandidateLinuxTransportBundle";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u;
const PRODUCTION_PATHS = Object.freeze({
  trustRoot: "/etc/ti-scale/candidate-linux",
  profile: "/etc/ti-scale/candidate-linux/profile.v1.json",
  manifest: "/etc/ti-scale/candidate-linux/manifest.v1.json",
  brokerEnvironment: "/etc/ti-scale/candidate-linux-broker.env",
  runtimeEnvironment: "/etc/ti-scale/candidate-linux-runtime.env",
  brokerExecutable:
    "/usr/local/libexec/ti-scale/disposable-candidate-linux-broker.js",
  brokerService:
    "/etc/systemd/system/ti-scale-candidate-linux-broker.service",
  applicationDropIn:
    "/etc/systemd/system/ti-scale.service.d/80-candidate-linux-transport.conf",
  stateFile: "/var/lib/ti-scale-candidate-linux/state/state.v1.json",
  userProof: "/var/lib/ti-scale-candidate-linux/fixture/user.txt",
  rootProof: "/var/lib/ti-scale-candidate-linux/fixture/root.txt",
  socket: "/run/ti-scale-candidate-linux/broker.sock",
});

interface Arguments {
  readonly execute: true;
  readonly databasePath: string;
  readonly postExploitSpecId: string;
  readonly brokerBundlePath: string;
  readonly brokerGid: number;
  readonly socketGid: number;
}

function parseArguments(argv: readonly string[]): Arguments {
  const values = new Map<string, string>();
  let execute = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--execute") {
      execute = true;
      continue;
    }
    if (!argument.startsWith("--") || !argv[index + 1]) {
      throw new Error(`Unsupported argument ${argument}`);
    }
    values.set(argument, argv[index + 1]!);
    index += 1;
  }
  if (!execute) {
    throw new Error(
      "Installation is explicit: add --execute. This command creates no backup.",
    );
  }
  const databasePath = values.get("--database-path") ?? "";
  const postExploitSpecId = values.get("--post-exploit-spec-id") ?? "";
  const brokerBundlePath = values.get("--broker-bundle-path") ?? "";
  const brokerGid = Number(values.get("--broker-gid"));
  const socketGid = Number(values.get("--socket-gid"));
  if (!isAbsolute(databasePath) || !isAbsolute(brokerBundlePath)) {
    throw new Error("Database and broker bundle paths must be absolute");
  }
  if (!ID.test(postExploitSpecId)) {
    throw new Error("The post-exploit spec ID is invalid");
  }
  if (
    !Number.isSafeInteger(brokerGid)
    || brokerGid < 1
    || !Number.isSafeInteger(socketGid)
    || socketGid < 1
    || brokerGid !== socketGid
  ) {
    throw new Error(
      "Broker and socket GIDs must be the same positive Ti-Scale service GID",
    );
  }
  return Object.freeze({
    execute: true,
    databasePath: resolve(databasePath),
    postExploitSpecId,
    brokerBundlePath: resolve(brokerBundlePath),
    brokerGid,
    socketGid,
  });
}

function writeOwned(
  path: string,
  bytes: string | Buffer,
  mode: number,
  gid: number,
): void {
  mkdirSync(resolve(path, ".."), { recursive: true, mode: 0o755 });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, bytes, { mode, flag: "wx" });
  chmodSync(temporary, mode);
  chownSync(temporary, 0, gid);
  renameSync(temporary, path);
}

const input = parseArguments(process.argv.slice(2));
if ((process.geteuid?.() ?? process.getuid?.() ?? -1) !== 0) {
  throw new Error("Root is required to create owner-controlled activation files");
}
const database = createDatabaseConnection({
  filename: input.databasePath,
  readonly: true,
  fileMustExist: true,
  verifyIntegrity: false,
});
try {
  const spec = database.prepare(`
    SELECT id, spec_hash, transport_binding_id, transport_type,
      expected_principal, expected_uid, declared_user_flag_path, status
    FROM candidate_linux_post_exploit_specs WHERE id = ?
  `).get(input.postExploitSpecId) as {
    readonly id: string;
    readonly spec_hash: string;
    readonly transport_binding_id: string;
    readonly transport_type: string;
    readonly expected_principal: string;
    readonly expected_uid: number;
    readonly declared_user_flag_path: string;
    readonly status: string;
  } | undefined;
  if (
    !spec
    || spec.status !== "active"
    || spec.transport_type !== "candidate_runtime_session_v1"
  ) {
    throw new Error(
      "The selected spec is not an active candidate-runtime Linux binding",
    );
  }
  mkdirSync(resolve(PRODUCTION_PATHS.brokerExecutable, ".."), {
    recursive: true,
    mode: 0o755,
  });
  copyFileSync(input.brokerBundlePath, PRODUCTION_PATHS.brokerExecutable);
  chmodSync(PRODUCTION_PATHS.brokerExecutable, 0o755);
  chownSync(PRODUCTION_PATHS.brokerExecutable, 0, 0);
  const userProofBytes = Buffer.from(
    "ti-scale disposable user objective proof v1\n",
    "utf8",
  );
  const rootProofBytes = Buffer.from(
    "ti-scale disposable root objective proof v1\n",
    "utf8",
  );
  const bundle = createDisposableCandidateLinuxTransportBundle({
    bundleVersion: "disposable-local-proof-1",
    profileId: "profile:disposable-local-linux-v1",
    bindingId: spec.transport_binding_id,
    postExploitSpecId: spec.id,
    postExploitSpecSha256: spec.spec_hash,
    exactTarget: "127.0.0.2",
    expectedPrincipal: spec.expected_principal,
    expectedUid: spec.expected_uid,
    expectedGid: spec.expected_uid,
    expectedGroups: Object.freeze([spec.expected_principal]),
    declaredUserFlagPath: spec.declared_user_flag_path,
    brokerExecutablePath: PRODUCTION_PATHS.brokerExecutable,
    brokerSocketPath: PRODUCTION_PATHS.socket,
    brokerSocketGid: input.socketGid,
    handlerProfilePath: PRODUCTION_PATHS.profile,
    userProofFilePath: PRODUCTION_PATHS.userProof,
    rootProofFilePath: PRODUCTION_PATHS.rootProof,
    stateFilePath: PRODUCTION_PATHS.stateFile,
    userProofBytes,
    rootProofBytes,
  });
  writeOwned(
    PRODUCTION_PATHS.userProof,
    userProofBytes,
    0o640,
    input.brokerGid,
  );
  writeOwned(
    PRODUCTION_PATHS.rootProof,
    rootProofBytes,
    0o640,
    input.brokerGid,
  );
  writeOwned(
    PRODUCTION_PATHS.profile,
    bundle.profileBytes,
    0o640,
    input.brokerGid,
  );
  writeOwned(
    PRODUCTION_PATHS.manifest,
    bundle.manifestBytes,
    0o640,
    input.brokerGid,
  );
  writeOwned(
    PRODUCTION_PATHS.brokerEnvironment,
    [
      `TI_SCALE_CANDIDATE_LINUX_TRUST_ROOT=${PRODUCTION_PATHS.trustRoot}`,
      `TI_SCALE_CANDIDATE_LINUX_MANIFEST_PATH=${PRODUCTION_PATHS.manifest}`,
      `TI_SCALE_CANDIDATE_LINUX_MANIFEST_SHA256=${bundle.manifestSha256}`,
      `TI_SCALE_DATABASE_PATH=${input.databasePath}`,
      "",
    ].join("\n"),
    0o640,
    input.brokerGid,
  );
  writeOwned(
    PRODUCTION_PATHS.runtimeEnvironment,
    [
      `TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_TRUST_ROOT=${PRODUCTION_PATHS.trustRoot}`,
      `TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_MANIFEST_PATH=${PRODUCTION_PATHS.manifest}`,
      `TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_MANIFEST_SHA256=${bundle.manifestSha256}`,
      "",
    ].join("\n"),
    0o640,
    0,
  );
  const sourceRoot = resolve(import.meta.dir, "..");
  for (const [source, destination] of [
    [
      resolve(
        sourceRoot,
        "deployment/systemd/ti-scale-candidate-linux-broker.service",
      ),
      PRODUCTION_PATHS.brokerService,
    ],
    [
      resolve(
        sourceRoot,
        "deployment/systemd/ti-scale.service.d/80-candidate-linux-transport.conf",
      ),
      PRODUCTION_PATHS.applicationDropIn,
    ],
  ] as const) {
    writeOwned(destination, readFileSync(source), 0o644, 0);
  }
  process.stdout.write(`${JSON.stringify({
    status: "installed_not_activated",
    backupCreated: false,
    candidateClass: "disposable_local_fixture_v1",
    readinessScope: "production_path_proof_only",
    realTargetSupport: false,
    missionExecutionReady: false,
    manifestPath: PRODUCTION_PATHS.manifest,
    manifestSha256: bundle.manifestSha256,
    profilePath: PRODUCTION_PATHS.profile,
    profileSha256: bundle.profileSha256,
    brokerExecutablePath: PRODUCTION_PATHS.brokerExecutable,
    brokerExecutableSha256: bundle.brokerExecutableSha256,
    socketPath: PRODUCTION_PATHS.socket,
    nextRequiredAction:
      "Explicitly reload systemd, start the candidate broker, attest it, and only then restart Ti-Scale.",
  }, null, 2)}\n`);
} finally {
  database.close();
}
