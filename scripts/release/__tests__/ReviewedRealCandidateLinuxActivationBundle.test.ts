import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, type SqliteDatabase } from "../../../server/db";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
  candidateLinuxPostExploitSpecificationHash,
  reviewedRealCandidateLinuxOperations,
} from "../../../server/autonomous-runtime";
import {
  exactCandidateLinuxTargetScope,
} from "../../../server/autonomous-runtime/CandidateLinuxTargetScope";
import {
  parseReviewedRealCandidateLinuxActivationArguments,
  reviewedRealCandidateLinuxActivationUsage,
} from "../../install-reviewed-real-candidate-linux-activation";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
  ReviewedRealCandidateLinuxActivationInstaller,
  prepareReviewedRealCandidateLinuxActivation,
  reviewedRealCandidateLinuxSystemdFiles,
  type ReviewedRealCandidateLinuxActivationInput,
  type ReviewedRealCandidateLinuxActivationPaths,
} from "../ReviewedRealCandidateLinuxActivationBundle";

const roots: string[] = [];
const databases: SqliteDatabase[] = [];
const SCRIPT_HASH = "a".repeat(64);
const CONTRACT_HASH = "c".repeat(64);
const BINDING_ID = "binding.reviewed-real.install-test";
const SPEC_ID = "spec.reviewed-real.install-test";
const SCRIPT_ID = "script.reviewed-real.install-test";
const OBSERVER_ID = "observer.reviewed-real.install-test";
const SERVICE_GID = (process.getgid?.() ?? 0) > 0
  ? process.getgid!()
  : 1;

afterEach(() => {
  while (databases.length) databases.pop()!.close();
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function registerFixtureSpec(database: SqliteDatabase): void {
  const specHash = candidateLinuxPostExploitSpecificationHash({
    exploitOutcomeObserverSpecId: OBSERVER_ID,
    scriptArtifactId: SCRIPT_ID,
    scriptContentHash: SCRIPT_HASH,
    transportType: "candidate_runtime_session_v1",
    transportBindingId: BINDING_ID,
    transportOrigin: null,
    expectedPrincipal: "operator",
    expectedUid: 1_000,
    declaredUserFlagPath: "/home/operator/user.txt",
  });
  database.prepare(`
    INSERT INTO candidate_linux_post_exploit_specs VALUES (
      ?, ?, ?, 'candidate_runtime_session_v1', ?, NULL,
      'operator', 1000, '/home/operator/user.txt', '/root/root.txt',
      ?, 'active'
    )
  `).run(SPEC_ID, OBSERVER_ID, SCRIPT_ID, BINDING_ID, specHash);
}

function createDatabase(registered = false): SqliteDatabase {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  database.exec(`
    CREATE TABLE missions (
      id TEXT PRIMARY KEY,
      authorization_status TEXT NOT NULL,
      control_plane TEXT NOT NULL
    );
    CREATE TABLE mission_contracts (
      id TEXT PRIMARY KEY,
      mission_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      contract_hash TEXT NOT NULL,
      state TEXT NOT NULL
    );
    CREATE TABLE runs (
      id TEXT PRIMARY KEY,
      mission_id TEXT NOT NULL,
      journey TEXT NOT NULL,
      control_plane TEXT NOT NULL,
      contract_id TEXT,
      contract_version_bound INTEGER,
      contract_hash_bound TEXT
    );
    CREATE TABLE script_artifacts (
      id TEXT PRIMARY KEY,
      content_hash TEXT NOT NULL,
      validation_state TEXT NOT NULL,
      mission_id TEXT NOT NULL,
      run_id TEXT
    );
    CREATE TABLE exploit_outcome_observer_specs (
      id TEXT PRIMARY KEY,
      script_artifact_id TEXT NOT NULL,
      script_content_hash TEXT NOT NULL,
      status TEXT NOT NULL
    );
    CREATE TABLE candidate_linux_post_exploit_specs (
      id TEXT PRIMARY KEY,
      exploit_outcome_observer_spec_id TEXT NOT NULL,
      script_artifact_id TEXT NOT NULL,
      transport_type TEXT NOT NULL,
      transport_binding_id TEXT NOT NULL,
      transport_origin TEXT,
      expected_principal TEXT NOT NULL,
      expected_uid INTEGER NOT NULL,
      declared_user_flag_path TEXT NOT NULL,
      declared_root_flag_path TEXT NOT NULL,
      spec_hash TEXT NOT NULL,
      status TEXT NOT NULL
    );
  `);
  database.prepare(`
    INSERT INTO missions VALUES ('mission:test', 'verified', 'ti_scale')
  `).run();
  database.prepare(`
    INSERT INTO mission_contracts
    VALUES ('contract:test', 'mission:test', 3, ?, 'confirmed')
  `).run(CONTRACT_HASH);
  database.prepare(`
    INSERT INTO runs VALUES (
      'run:test', 'mission:test', 'autonomous', 'ti_scale',
      'contract:test', 3, ?
    )
  `).run(CONTRACT_HASH);
  database.prepare(`
    INSERT INTO script_artifacts VALUES (
      ?, ?, 'approved', 'mission:test', 'run:test'
    )
  `).run(SCRIPT_ID, SCRIPT_HASH);
  database.prepare(`
    INSERT INTO exploit_outcome_observer_specs
    VALUES (?, ?, ?, 'active')
  `).run(OBSERVER_ID, SCRIPT_ID, SCRIPT_HASH);
  if (registered) registerFixtureSpec(database);
  return database;
}

function mkdirTrusted(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

function fixture(registered = false): Readonly<{
  input: ReviewedRealCandidateLinuxActivationInput;
  paths: ReviewedRealCandidateLinuxActivationPaths;
}> {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-reviewed-activation-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const sourceRoot = join(root, "reviewed-source");
  const destination = join(root, "destination");
  mkdirTrusted(sourceRoot);
  mkdirTrusted(destination);
  for (const directory of ["bin", "env", "systemd", "dropin"]) {
    mkdirTrusted(join(destination, directory));
  }
  const paths: ReviewedRealCandidateLinuxActivationPaths = Object.freeze({
    trustRoot: join(destination, "trust"),
    profile: join(destination, "trust", "profile.v1.json"),
    manifest: join(destination, "trust", "manifest.v1.json"),
    receipt: join(destination, "trust", "installation-receipt.v1.json"),
    adapterEnvironment: join(destination, "env", "adapter.env"),
    brokerEnvironment: join(destination, "env", "broker.env"),
    runtimeEnvironment: join(destination, "env", "runtime.env"),
    adapterExecutable: join(destination, "bin", "adapter"),
    procedureTrustRoot: join(root, "state", "procedures"),
    procedureExecutable: join(destination, "bin", "procedure"),
    brokerExecutable: join(destination, "bin", "broker"),
    registerExecutable: join(destination, "bin", "register"),
    adapterSocket: join(root, "run", "adapter.sock"),
    brokerSocket: join(root, "run", "broker.sock"),
    adapterService: join(destination, "systemd", "adapter.service"),
    brokerService: join(destination, "systemd", "broker.service"),
    applicationDropIn: join(destination, "dropin", "transport.conf"),
  });
  const adapterPath = join(sourceRoot, "candidate-adapter");
  const brokerPath = join(sourceRoot, "candidate-broker");
  const procedurePath = join(sourceRoot, "candidate-procedure");
  const registerPath = join(sourceRoot, "candidate-register");
  writeFileSync(adapterPath, "#!/bin/false\nreviewed adapter\n", { mode: 0o500 });
  writeFileSync(
    procedurePath,
    "#!/bin/false\nreviewed typed candidate procedure\n",
    { mode: 0o500 },
  );
  writeFileSync(brokerPath, "#!/bin/false\nreviewed broker\n", { mode: 0o500 });
  writeFileSync(registerPath, "#!/bin/false\nreviewed register\n", { mode: 0o500 });
  const adapterHash = sha256(readFileSync(adapterPath));
  const procedureHash = sha256(readFileSync(procedurePath));
  const specHash = candidateLinuxPostExploitSpecificationHash({
    exploitOutcomeObserverSpecId: OBSERVER_ID,
    scriptArtifactId: SCRIPT_ID,
    scriptContentHash: SCRIPT_HASH,
    transportType: "candidate_runtime_session_v1",
    transportBindingId: BINDING_ID,
    transportOrigin: null,
    expectedPrincipal: "operator",
    expectedUid: 1_000,
    declaredUserFlagPath: "/home/operator/user.txt",
  });
  const profile = {
    schemaVersion: REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId: "profile.reviewed-real.install-test",
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: exactCandidateLinuxTargetScope("127.0.0.1"),
    bindingId: BINDING_ID,
    postExploitSpec: {
      id: SPEC_ID,
      expectedSha256: specHash,
      exploitOutcomeObserverSpecId: OBSERVER_ID,
      scriptArtifactId: SCRIPT_ID,
      expectedPrincipal: "operator",
      expectedUid: 1_000,
      declaredUserFlagPath: "/home/operator/user.txt",
      declaredRootFlagPath: "/root/root.txt",
    },
    adapter: {
      executablePath: paths.adapterExecutable,
      executableSha256: adapterHash,
      socketPath: paths.adapterSocket,
      socketGid: SERVICE_GID,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
    },
    procedure: {
      executablePath: paths.procedureExecutable,
      executableSha256: procedureHash,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
    },
    boundary: {
      typedOperationsOnly: true,
      genericCommand: false,
      shell: false,
      argv: false,
      payload: false,
      credentialsFromRuntime: false,
      exactTargetFromCanonicalAction: true,
      succeededAttackAttemptRequired: true,
      derivedCurrentRunSpecOnly: true,
      publicProvider: false,
      hashOnlyFlagProofs: true,
    },
    operations: reviewedRealCandidateLinuxOperations(),
  };
  const profilePath = join(sourceRoot, "profile.v1.json");
  const profileBytes = `${JSON.stringify(profile, null, 2)}\n`;
  writeFileSync(profilePath, profileBytes, { mode: 0o400 });
  return Object.freeze({
    paths,
    input: Object.freeze({
      bundleVersion: "candidate-install-test-v1",
      database: createDatabase(registered),
      databasePath: join(root, "canonical.sqlite"),
      serviceGid: SERVICE_GID,
      paths,
      installedOwnerUid: process.geteuid?.() ?? process.getuid?.() ?? 0,
      source: Object.freeze({
        trustRoot: sourceRoot,
        profilePath,
        profileSha256: sha256(profileBytes),
        adapterExecutablePath: adapterPath,
        adapterExecutableSha256: adapterHash,
        procedureExecutablePath: procedurePath,
        procedureExecutableSha256: sha256(readFileSync(procedurePath)),
        brokerExecutablePath: brokerPath,
        brokerExecutableSha256: sha256(readFileSync(brokerPath)),
        registerExecutablePath: registerPath,
        registerExecutableSha256: sha256(readFileSync(registerPath)),
        allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
      }),
    }),
  });
}

describe("reviewed real-candidate Linux activation bundle", () => {
  test("keeps the checked-in systemd policy identical to the deterministic fixed-path templates", () => {
    const generated = reviewedRealCandidateLinuxSystemdFiles(
      REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS,
    );
    expect(readFileSync(
      "deployment/systemd/ti-scale-reviewed-candidate-linux-adapter.service",
      "utf8",
    )).toBe(generated.adapterService);
    expect(readFileSync(
      "deployment/systemd/ti-scale-reviewed-candidate-linux-broker.service",
      "utf8",
    )).toBe(generated.brokerService);
    expect(readFileSync(
      "deployment/systemd/ti-scale.service.d/81-reviewed-candidate-linux-transport.conf",
      "utf8",
    )).toBe(generated.applicationDropIn);
    expect(generated.adapterService).toContain("NoNewPrivileges=yes");
    expect(generated.adapterService).toContain("Type=notify");
    expect(generated.adapterService).toContain("NotifyAccess=all");
    expect(generated.adapterService).toContain("PartOf=ti-scale.service");
    expect(generated.adapterService).toContain(
      `AssertPathExists=${REVIEWED_REAL_CANDIDATE_LINUX_PRODUCTION_PATHS.adapterExecutable}`,
    );
    expect(generated.adapterService).toContain(
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    );
    expect(generated.adapterService).toContain(
      "ReadWritePaths=/run/ti-scale-candidate-linux-reviewed /var/lib/ti-scale-candidate-linux-reviewed /var/lib/ti-scale/data",
    );
    expect(generated.brokerService).toContain("Type=notify");
    expect(generated.brokerService).toContain("NotifyAccess=all");
    expect(generated.brokerService).toContain(
      "RestrictAddressFamilies=AF_UNIX",
    );
    expect(generated.brokerService).toContain(
      "Requires=ti-scale-reviewed-candidate-linux-adapter.service",
    );
    expect(generated.applicationDropIn).toContain(
      "Requires=ti-scale-reviewed-candidate-linux-broker.service",
    );
    expect(generated.applicationDropIn).toContain(
      "BindsTo=ti-scale-reviewed-candidate-linux-broker.service",
    );
    expect(generated.applicationDropIn).not.toContain(
      "Wants=ti-scale-reviewed-candidate-linux-broker.service",
    );
    expect(`${generated.adapterService}${generated.brokerService}`)
      .not.toMatch(/ExecStart=.*(?:sh|bash)\s/u);
    const adapterEntrypoint = readFileSync(
      "server/autonomous-runtime/reviewed-real-candidate-linux-adapter-cli.ts",
      "utf8",
    );
    expect(adapterEntrypoint.indexOf(
      "await startReviewedRealCandidateLinuxAdapter",
    )).toBeLessThan(
      adapterEntrypoint.indexOf("notifySystemdServiceReady("),
    );
    const brokerEntrypoint = readFileSync(
      "server/autonomous-runtime/reviewed-real-candidate-linux-broker-cli.ts",
      "utf8",
    );
    expect(
      brokerEntrypoint.indexOf("await registry.attest("),
    ).toBeLessThan(
      brokerEntrypoint.indexOf("notifySystemdServiceReady("),
    );
  });

  test("prepares and publishes only exact owner-controlled files, never activation", () => {
    const { input, paths } = fixture(true);
    const installer = new ReviewedRealCandidateLinuxActivationInstaller(input);
    const prepared = installer.prepare();
    expect(prepared.receipt).toMatchObject({
      status: "installed_not_activated",
      backupCreated: false,
      databaseMutated: false,
      systemdReloaded: false,
      servicesStarted: false,
      realTargetSupport: true,
      targetScope: exactCandidateLinuxTargetScope("127.0.0.1"),
      missionExecutionReady: false,
      conditionalCapability: true,
      candidateProcedurePresentAtLaunch: true,
      procedureProviderPresentAtLaunch: true,
      runScopedProcedureActivationPresentAtLaunch: false,
      runScopedProcedureTrustRoot: paths.procedureTrustRoot,
      sourceAuthority: {
        sourceSpecIdentityVerified: true,
        contractHash: CONTRACT_HASH,
        bindingId: BINDING_ID,
      },
      procedure: {
        path: paths.procedureExecutable,
        sha256: input.source.procedureExecutableSha256,
      },
      invocationAuthority: {
        exactTarget: "current_canonical_action_only",
        run: "current_derived_spec_only",
        contract: "current_confirmed_hash_bound_contract_only",
      },
    });
    expect(installer.install()).toEqual(prepared.receipt);
    expect(installer.verifyInstalled()).toEqual(prepared.receipt);
    expect(readFileSync(paths.adapterExecutable)).toEqual(
      readFileSync(input.source.adapterExecutablePath),
    );
    expect(readFileSync(paths.registerExecutable)).toEqual(
      readFileSync(input.source.registerExecutablePath),
    );
    expect(readFileSync(paths.procedureExecutable)).toEqual(
      readFileSync(input.source.procedureExecutablePath),
    );
    expect(readFileSync(paths.adapterEnvironment, "utf8")).toContain(
      `TI_SCALE_CANDIDATE_LINUX_PROCEDURE_TRUST_ROOT=${paths.procedureTrustRoot}`,
    );
    expect(readFileSync(paths.adapterEnvironment, "utf8")).toContain(
      `TI_SCALE_DATABASE_PATH=${input.databasePath}`,
    );
    expect(readFileSync(paths.adapterService, "utf8")).toContain(
      ` ${dirname(input.databasePath)}`,
    );
    expect(readFileSync(paths.adapterEnvironment, "utf8")).not.toContain(
      "TI_SCALE_CANDIDATE_LINUX_PROCEDURE_SHA256",
    );
    expect(installer.install()).toEqual(prepared.receipt);
    expect(
      prepared.files.some(({ path }) =>
        /backup|snapshot|rollback/u.test(path)),
    ).toBeFalse();
  });

  test("makes exact reinstall idempotent and rejects a partial destination", () => {
    const exact = fixture(true);
    const exactInstaller =
      new ReviewedRealCandidateLinuxActivationInstaller(exact.input);
    const receipt = exactInstaller.install();
    expect(exactInstaller.install()).toEqual(receipt);
    expect(exactInstaller.verifyInstalled()).toEqual(receipt);
    chmodSync(dirname(exact.paths.adapterExecutable), 0o777);
    expect(() => exactInstaller.verifyInstalled()).toThrow(
      "Installation parent is not owner-controlled",
    );

    const partial = fixture(true);
    mkdirSync(partial.paths.trustRoot, { mode: 0o750 });
    chmodSync(partial.paths.trustRoot, 0o750);
    expect(() =>
      new ReviewedRealCandidateLinuxActivationInstaller(
        partial.input,
      ).install()
    ).toThrow("installation is partial or conflicts");
  });

  test("keeps the installed receipt stable across exact registration and retry", () => {
    const exact = fixture(false);
    const installer =
      new ReviewedRealCandidateLinuxActivationInstaller(exact.input);
    const beforeRegistration = installer.install();
    expect(beforeRegistration.sourceAuthority).toMatchObject({
      sourceSpecIdentityVerified: true,
      postExploitSpecId: SPEC_ID,
      bindingId: BINDING_ID,
    });
    registerFixtureSpec(exact.input.database);
    expect(installer.verifyInstalled()).toEqual(beforeRegistration);
    expect(installer.install()).toEqual(beforeRegistration);
  });

  test("validates the DB lineage and recomputed spec before any destination write", () => {
    const { input, paths } = fixture();
    expect(
      prepareReviewedRealCandidateLinuxActivation(input)
        .receipt.sourceAuthority.sourceSpecIdentityVerified,
    ).toBeTrue();
    input.database.prepare(`
      UPDATE script_artifacts SET content_hash = ?
      WHERE id = ?
    `).run("b".repeat(64), SCRIPT_ID);
    expect(() =>
      prepareReviewedRealCandidateLinuxActivation(input)
    ).toThrow(
      "Profile ScriptArtifact, observer, autonomous run, or confirmed contract identity is not current",
    );
    expect(existsSync(paths.trustRoot)).toBeFalse();
    expect(existsSync(paths.adapterExecutable)).toBeFalse();
  });

  test("CLI requires all pins and makes install the only explicit mutation", () => {
    const hash = "a".repeat(64);
    const pins = [
      "--bundle-version", "candidate-v1",
      "--database-path", "/var/lib/ti-scale/data/ti-scale.sqlite",
      "--service-gid", "1001",
      "--source-trust-root", "/root/reviewed-candidate",
      "--profile-path", "/root/reviewed-candidate/profile.json",
      "--profile-sha256", hash,
      "--adapter-path", "/root/reviewed-candidate/adapter",
      "--adapter-sha256", hash,
      "--procedure-path", "/root/reviewed-candidate/procedure",
      "--procedure-sha256", hash,
      "--broker-path", "/root/reviewed-candidate/broker",
      "--broker-sha256", hash,
      "--register-path", "/root/reviewed-candidate/register",
      "--register-sha256", hash,
    ];
    expect(parseReviewedRealCandidateLinuxActivationArguments([
      "source-verify",
      ...pins,
    ])).toMatchObject({ operation: "source-verify", execute: false });
    expect(parseReviewedRealCandidateLinuxActivationArguments([
      "install",
      "--execute",
      ...pins,
    ])).toMatchObject({ operation: "install", execute: true });
    expect(() =>
      parseReviewedRealCandidateLinuxActivationArguments([
        "install",
        ...pins,
      ])
    ).toThrow("requires the explicit --execute");
    expect(reviewedRealCandidateLinuxActivationUsage()).toContain(
      "never reloads, enables, starts, or restarts systemd",
    );
  });
});
