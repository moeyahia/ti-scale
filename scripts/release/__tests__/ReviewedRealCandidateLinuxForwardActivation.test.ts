import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterEach,
  describe,
  expect,
  test,
} from "bun:test";
import {
  exactCandidateLinuxTargetScope,
} from "../../../server/autonomous-runtime/CandidateLinuxTargetScope";
import {
  parseReviewedRealCandidateLinuxForwardActivationArguments,
  reviewedRealCandidateLinuxForwardActivationUsage,
} from "../../activate-reviewed-real-candidate-linux";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_SCHEMA_VERSION,
  type PreparedReviewedRealCandidateLinuxActivation,
  type ReviewedRealCandidateLinuxActivationReceipt,
} from "../ReviewedRealCandidateLinuxActivationBundle";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_CONFIRMATION,
  REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT,
  REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT,
  ReviewedCandidateLiveActivationVerifier,
  ReviewedRealCandidateLinuxForwardActivation,
  TI_SCALE_APPLICATION_FRAGMENT,
  TI_SCALE_APPLICATION_ORIGIN,
  TI_SCALE_APPLICATION_UNIT,
  assertReviewedCandidateActivationCommand,
  type ReviewedCandidateActivationCommandPort,
  type ReviewedCandidateActivationInstallerPort,
  type ReviewedCandidateActivationVerifierPort,
} from "../ReviewedRealCandidateLinuxForwardActivation";
import type {
  ActiveV2Work,
} from "../FunctionalReleasePrimitives";

const roots: string[] = [];
const HASH = "a".repeat(64);
const NOW = new Date("2026-07-29T12:00:00.000Z");
const TARGET_SCOPE = exactCandidateLinuxTargetScope("127.0.0.2");
const IDLE_WORK: ActiveV2Work = Object.freeze({
  activeRuns: Object.freeze([]),
  activeLeases: Object.freeze([]),
  activeDatabaseWriters: Object.freeze([]),
  reconciliationRequired: Object.freeze([]),
});

afterEach(() => {
  while (roots.length) {
    rmSync(roots.pop()!, { recursive: true, force: true });
  }
});

function paths(root: string) {
  return Object.freeze({
    trustRoot: join(root, "trust"),
    profile: join(root, "trust/profile.json"),
    manifest: join(root, "trust/manifest.json"),
    receipt: join(root, "trust/receipt.json"),
    adapterEnvironment: join(root, "adapter.env"),
    brokerEnvironment: join(root, "broker.env"),
    runtimeEnvironment: join(root, "runtime.env"),
    adapterExecutable: join(root, "adapter"),
    procedureTrustRoot: join(root, "procedures"),
    procedureExecutable: join(root, "procedure"),
    brokerExecutable: join(root, "broker"),
    registerExecutable: join(root, "register"),
    adapterSocket: join(root, "adapter.sock"),
    brokerSocket: join(root, "broker.sock"),
    adapterService: join(root, "adapter.service"),
    brokerService: join(root, "broker.service"),
    applicationDropIn: join(root, "application.conf"),
  });
}

function preparedFixture(root: string):
PreparedReviewedRealCandidateLinuxActivation {
  const fixturePaths = paths(root);
  const receipt = {
    schemaVersion:
      REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_SCHEMA_VERSION,
    bundleVersion: "candidate-forward-activation-test-v1",
    status: "installed_not_activated",
    backupCreated: false,
    databaseMutated: false,
    systemdReloaded: false,
    servicesStarted: false,
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: TARGET_SCOPE,
    missionExecutionReady: false,
    conditionalCapability: true,
    candidateProcedurePresentAtLaunch: true,
    procedureProviderPresentAtLaunch: true,
    runScopedProcedureActivationPresentAtLaunch: false,
    runScopedProcedureTrustRoot: fixturePaths.procedureTrustRoot,
    sourceAuthority: {
      missionId: "mission:test",
      runId: "run:test",
      contractId: "contract:test",
      contractVersion: 1,
      contractHash: HASH,
      scriptArtifactId: "script:test",
      scriptContentHash: HASH,
      observerSpecId: "observer:test",
      postExploitSpecId: "spec:test",
      postExploitSpecSha256: HASH,
      bindingId: "binding:test",
      sourceSpecIdentityVerified: true,
    },
    profile: { path: fixturePaths.profile, sha256: HASH },
    manifest: { path: fixturePaths.manifest, sha256: HASH },
    adapter: {
      path: fixturePaths.adapterExecutable,
      sha256: HASH,
      socketPath: fixturePaths.adapterSocket,
    },
    procedure: {
      path: fixturePaths.procedureExecutable,
      sha256: HASH,
    },
    broker: {
      path: fixturePaths.brokerExecutable,
      sha256: HASH,
      socketPath: fixturePaths.brokerSocket,
    },
    register: {
      path: fixturePaths.registerExecutable,
      sha256: HASH,
    },
    invocationAuthority: {
      exactTarget: "current_canonical_action_only",
      run: "current_derived_spec_only",
      contract: "current_confirmed_hash_bound_contract_only",
      attackAttempt: "succeeded_with_verified_outcome_evidence_only",
      cancellation: "abort_signal_and_lease_fence_required",
    },
  } satisfies ReviewedRealCandidateLinuxActivationReceipt;
  return {
    profile: {} as PreparedReviewedRealCandidateLinuxActivation["profile"],
    manifest: {
      schemaVersion: "ti-scale.candidate-linux-transport-binding-manifest.v1",
      bundleVersion: receipt.bundleVersion,
      broker: {} as PreparedReviewedRealCandidateLinuxActivation["manifest"]["broker"],
      boundary: {} as PreparedReviewedRealCandidateLinuxActivation["manifest"]["boundary"],
      bindings: [{
        bindingId: "binding:test",
        postExploitSpecId: "spec:test",
        postExploitSpecSha256: HASH,
        candidateClass: "reviewed_real_candidate_v1",
        handlerProfilePath: fixturePaths.profile,
        handlerProfileSha256: HASH,
        realTargetSupport: true,
        targetScope: TARGET_SCOPE,
        operations: [],
      }],
    },
    manifestSha256: HASH,
    receipt,
    files: Object.freeze([
      Object.freeze({
        path: fixturePaths.profile,
        bytes: Buffer.from("profile"),
        mode: 0o440,
        gid: 1,
      }),
      Object.freeze({
        path: fixturePaths.adapterService,
        bytes: Buffer.from("unit"),
        mode: 0o644,
        gid: 0,
      }),
    ]),
  } as PreparedReviewedRealCandidateLinuxActivation;
}

class FakeInstaller implements ReviewedCandidateActivationInstallerPort {
  installCalls = 0;
  verifyCalls = 0;
  failVerificationAt = 0;

  constructor(readonly prepared: PreparedReviewedRealCandidateLinuxActivation) {}

  prepare(): PreparedReviewedRealCandidateLinuxActivation {
    return this.prepared;
  }

  install(): ReviewedRealCandidateLinuxActivationReceipt {
    this.installCalls += 1;
    return this.prepared.receipt;
  }

  verifyInstalled(): ReviewedRealCandidateLinuxActivationReceipt {
    this.verifyCalls += 1;
    if (this.verifyCalls === this.failVerificationAt) {
      throw new Error("installed file identity drifted");
    }
    return this.prepared.receipt;
  }
}

class FakeCommands implements ReviewedCandidateActivationCommandPort {
  readonly calls: readonly string[][] = [];
  wrongFragment = false;
  wrongApplicationDropIn = false;

  constructor(
    readonly fixturePaths: ReturnType<typeof paths>,
    readonly prepared: PreparedReviewedRealCandidateLinuxActivation,
  ) {}

  async run(command: readonly string[]): Promise<{
    stdout: string;
    stderr: string;
  }> {
    (this.calls as string[][]).push([...command]);
    if (command[0] === "/usr/sbin/runuser") {
      return {
        stdout: JSON.stringify({
          status: "registered",
          manifestSha256: this.prepared.manifestSha256,
          records: [{
            id: "spec:test",
            specHash: HASH,
            transportBindingId: "binding:test",
          }],
        }),
        stderr: "",
      };
    }
    if (command[1] === "show") {
      const unit = command[2]!;
      const fragment = unit === REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT
        ? this.fixturePaths.adapterService
        : unit === REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT
          ? this.fixturePaths.brokerService
          : "/etc/systemd/system/ti-scale.service";
      return {
        stdout: [
          `Id=${unit}`,
          "LoadState=loaded",
          "ActiveState=active",
          "SubState=running",
          "Result=success",
          "MainPID=1234",
          `FragmentPath=${this.wrongFragment ? "/tmp/drift.service" : fragment}`,
          `DropInPaths=${
            unit === TI_SCALE_APPLICATION_UNIT
              ? this.wrongApplicationDropIn
                ? "/tmp/drift.conf"
                : this.fixturePaths.applicationDropIn
              : ""
          }`,
          `UnitFileState=${unit === TI_SCALE_APPLICATION_UNIT ? "static" : "enabled"}`,
          "NeedDaemonReload=no",
        ].join("\n"),
        stderr: "",
      };
    }
    return { stdout: "", stderr: "" };
  }
}

function verifier(
  prepared: PreparedReviewedRealCandidateLinuxActivation,
): ReviewedCandidateActivationVerifierPort {
  return {
    async verifyCandidate() {
      return {
        status: "ready",
        code: "candidate_linux_transport_ready",
        readinessScope: "reviewed_real_candidate",
        activationModel: "run_scoped_after_discovery",
        conditionalPlanningReady: true,
        missionExecutionReady: false,
        manifestSha256: prepared.manifestSha256,
        bindingIds: ["binding:test"],
        targetScopes: [TARGET_SCOPE],
        expiresAt: "2026-07-29T12:01:00.000Z",
      };
    },
    async verifyApplication() {
      return {
        origin: TI_SCALE_APPLICATION_ORIGIN,
        liveness: "healthy",
        readiness: "healthy",
        databaseHealthy: true,
        eventStreamHealthy: true,
        authenticationConfigured: true,
        authenticatedRoundTrip: true,
        actorId: "operator",
        sessionExpiresAt: "2026-07-29T13:00:00.000Z",
      };
    },
  };
}

function pins(): string[] {
  return [
    "--bundle-version", "candidate-v1",
    "--database-path", "/var/lib/ti-scale/data/ti-scale.sqlite",
    "--service-gid", "1001",
    "--source-trust-root", "/root/reviewed-candidate",
    "--profile-path", "/root/reviewed-candidate/profile.json",
    "--profile-sha256", HASH,
    "--adapter-path", "/root/reviewed-candidate/adapter",
    "--adapter-sha256", HASH,
    "--procedure-path", "/root/reviewed-candidate/procedure",
    "--procedure-sha256", HASH,
    "--broker-path", "/root/reviewed-candidate/broker",
    "--broker-sha256", HASH,
    "--register-path", "/root/reviewed-candidate/register",
    "--register-sha256", HASH,
  ];
}

describe("reviewed real-candidate Linux forward activation", () => {
  test("parses inspect and requires the exact forward activation confirmation", () => {
    expect(parseReviewedRealCandidateLinuxForwardActivationArguments([
      "inspect",
      ...pins(),
    ])).toMatchObject({
      operation: "inspect",
      execute: false,
      installer: { operation: "verify-installed" },
    });
    expect(parseReviewedRealCandidateLinuxForwardActivationArguments([
      "activate",
      "--execute",
      "--confirmation",
      REVIEWED_REAL_CANDIDATE_LINUX_ACTIVATION_CONFIRMATION,
      ...pins(),
    ])).toMatchObject({
      operation: "activate",
      execute: true,
    });
    expect(() =>
      parseReviewedRealCandidateLinuxForwardActivationArguments([
        "activate",
        "--execute",
        ...pins(),
      ])
    ).toThrow("Activation requires");
    expect(() =>
      parseReviewedRealCandidateLinuxForwardActivationArguments([
        "inspect",
        "--execute",
        ...pins(),
      ])
    ).toThrow("inspect is read-only");
    expect(reviewedRealCandidateLinuxForwardActivationUsage())
      .toContain("No unrelated service is queried");
    expect(() =>
      assertReviewedCandidateActivationCommand([
        "/usr/bin/systemctl",
        "restart",
        TI_SCALE_APPLICATION_UNIT,
      ])
    ).not.toThrow();
    expect(() =>
      assertReviewedCandidateActivationCommand([
        "/usr/bin/systemctl",
        "restart",
        "chillspwn.service",
      ])
    ).toThrow("escaped the Ti-Scale 3132");
    expect(() =>
      assertReviewedCandidateActivationCommand([
        "/usr/bin/curl",
        "http://127.0.0.1:3131/api/health",
      ])
    ).toThrow("escaped the Ti-Scale 3132");
  });

  test("performs the exact idempotent ordered activation and live proof", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-forward-activation-"));
    roots.push(root);
    const fixturePaths = paths(root);
    const prepared = preparedFixture(root);
    const installer = new FakeInstaller(prepared);
    const commands = new FakeCommands(fixturePaths, prepared);
    const activation = new ReviewedRealCandidateLinuxForwardActivation({
      installer,
      commands,
      verifier: verifier(prepared),
      databasePath: "/var/lib/ti-scale/data/ti-scale.sqlite",
      paths: fixturePaths,
      readActiveWork: () => IDLE_WORK,
      clock: () => NOW,
    });
    const first = await activation.activate();
    const second = await activation.activate();
    expect(first).toEqual(second);
    expect(first).toMatchObject({
      status: "activated",
      backupCreated: false,
      rollbackPayloadCreated: false,
      port3131Touched: false,
      applicationOrigin: "http://127.0.0.1:3132",
      candidateTransport: {
        status: "ready",
        conditionalPlanningReady: true,
        missionExecutionReady: false,
      },
      application: {
        liveness: "healthy",
        readiness: "healthy",
        authenticatedRoundTrip: true,
      },
    });
    expect(installer.installCalls).toBe(2);
    expect(installer.verifyCalls).toBe(6);
    const operations = commands.calls.map((command) =>
      command[0] === "/usr/sbin/runuser"
        ? "register"
        : `${command[1]}:${command[2] ?? ""}`);
    expect(operations).toEqual([
      "register",
      "daemon-reload:",
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `show:${TI_SCALE_APPLICATION_UNIT}`,
      `enable:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `start:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `start:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `restart:${TI_SCALE_APPLICATION_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `show:${TI_SCALE_APPLICATION_UNIT}`,
      "register",
      "daemon-reload:",
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `show:${TI_SCALE_APPLICATION_UNIT}`,
      `enable:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `start:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `start:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `restart:${TI_SCALE_APPLICATION_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_UNIT}`,
      `show:${REVIEWED_REAL_CANDIDATE_LINUX_BROKER_UNIT}`,
      `show:${TI_SCALE_APPLICATION_UNIT}`,
    ]);
    expect(commands.calls.flat().join(" ").toLocaleLowerCase("en-US"))
      .not.toMatch(/3131|chillspwn|backup|snapshot|rollback/u);
  });

  test("fails before systemd on file drift and before enable on unit drift", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-forward-drift-"));
    roots.push(root);
    const fixturePaths = paths(root);
    const prepared = preparedFixture(root);
    const fileDrift = new FakeInstaller(prepared);
    fileDrift.failVerificationAt = 2;
    const fileCommands = new FakeCommands(fixturePaths, prepared);
    await expect(
      new ReviewedRealCandidateLinuxForwardActivation({
        installer: fileDrift,
        commands: fileCommands,
        verifier: verifier(prepared),
        paths: fixturePaths,
        readActiveWork: () => IDLE_WORK,
      }).activate(),
    ).rejects.toThrow("installed file identity drifted");
    expect(fileCommands.calls).toHaveLength(1);
    expect(fileCommands.calls[0]?.[0]).toBe("/usr/sbin/runuser");

    const unitCommands = new FakeCommands(fixturePaths, prepared);
    unitCommands.wrongFragment = true;
    await expect(
      new ReviewedRealCandidateLinuxForwardActivation({
        installer: new FakeInstaller(prepared),
        commands: unitCommands,
        verifier: verifier(prepared),
        paths: fixturePaths,
        readActiveWork: () => IDLE_WORK,
      }).activate(),
    ).rejects.toThrow("is not loaded from the exact installed unit");
    expect(unitCommands.calls.some((command) =>
      command[1] === "enable"
      || command[1] === "start"
      || command[1] === "restart")).toBeFalse();

    const applicationCommands = new FakeCommands(fixturePaths, prepared);
    applicationCommands.wrongApplicationDropIn = true;
    await expect(
      new ReviewedRealCandidateLinuxForwardActivation({
        installer: new FakeInstaller(prepared),
        commands: applicationCommands,
        verifier: verifier(prepared),
        paths: fixturePaths,
        readActiveWork: () => IDLE_WORK,
      }).activate(),
    ).rejects.toThrow("ti-scale.service is not loaded from the exact installed unit");
    expect(applicationCommands.calls.some((command) =>
      command[1] === "enable"
      || command[1] === "start"
      || command[1] === "restart")).toBeFalse();
    expect(TI_SCALE_APPLICATION_FRAGMENT)
      .toBe("/etc/systemd/system/ti-scale.service");
  });

  test("inspect reports absence and rejects a partial installation", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-forward-inspect-"));
    roots.push(root);
    const fixturePaths = paths(root);
    const prepared = preparedFixture(root);
    const absent = new ReviewedRealCandidateLinuxForwardActivation({
      installer: new FakeInstaller(prepared),
      commands: new FakeCommands(fixturePaths, prepared),
      verifier: verifier(prepared),
      paths: fixturePaths,
      readActiveWork: () => IDLE_WORK,
      exists: () => false,
    }).inspect();
    expect(absent).toMatchObject({
      status: "source_verified_installation_absent",
      installed: false,
      backupCreated: false,
      rollbackPayloadCreated: false,
      port3131Touched: false,
    });
    expect(() =>
      new ReviewedRealCandidateLinuxForwardActivation({
        installer: new FakeInstaller(prepared),
        commands: new FakeCommands(fixturePaths, prepared),
        verifier: verifier(prepared),
        paths: fixturePaths,
        readActiveWork: () => IDLE_WORK,
        exists: (path) => path === fixturePaths.trustRoot,
      }).inspect()
    ).toThrow("installation is partial");
  });

  test("refuses active runs, leases, and writers before any mutation", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-forward-active-work-"));
    roots.push(root);
    const fixturePaths = paths(root);
    const prepared = preparedFixture(root);
    const activeCases: readonly ActiveV2Work[] = [
      {
        ...IDLE_WORK,
        activeRuns: [{ id: "run:active", status: "running" }],
      },
      {
        ...IDLE_WORK,
        activeLeases: [{
          runId: "run:leased",
          expiresAt: "2099-01-01T00:00:00.000Z",
        }],
      },
      {
        ...IDLE_WORK,
        activeDatabaseWriters: [{
          kind: "runtime_continuation",
          id: "continuation:active",
          status: "processing",
          leaseExpiresAt: "2099-01-01T00:00:00.000Z",
        }],
      },
    ];
    for (const activeWork of activeCases) {
      const installer = new FakeInstaller(prepared);
      const commands = new FakeCommands(fixturePaths, prepared);
      await expect(
        new ReviewedRealCandidateLinuxForwardActivation({
          installer,
          commands,
          verifier: verifier(prepared),
          paths: fixturePaths,
          readActiveWork: () => activeWork,
        }).activate(),
      ).rejects.toThrow("Ti-Scale has active work");
      expect(installer.installCalls).toBe(0);
      expect(installer.verifyCalls).toBe(0);
      expect(commands.calls).toHaveLength(0);
    }
  });

  test("proves health, readiness, and an authenticated session only on 3132", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-forward-auth-"));
    roots.push(root);
    chmodSync(root, 0o700);
    const tokenPath = join(root, "operator-token");
    const token = "test-only-forward-activation-token";
    writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    chmodSync(tokenPath, 0o600);
    const requests: Array<{
      path: string;
      method: string;
      authenticated: boolean;
    }> = [];
    const verifierInstance = new ReviewedCandidateLiveActivationVerifier({
      tokenPath,
      tokenTrustRoot: root,
      deadlineMs: 1_000,
      requestTimeoutMs: 250,
      pollIntervalMs: 1,
      fetch: async (input, init) => {
        const url = new URL(String(input));
        const headers = new Headers(init?.headers);
        const method = init?.method ?? "GET";
        requests.push({
          path: url.pathname,
          method,
          authenticated: headers.get("Cookie")?.includes(
            "ti_scale_session=",
          ) === true,
        });
        expect(url.origin).toBe(TI_SCALE_APPLICATION_ORIGIN);
        if (url.pathname === "/api/v2/health") {
          return Response.json({
            schemaVersion: "2.4",
            status: "healthy",
            database: { healthy: true },
            eventStream: { status: "healthy" },
          });
        }
        if (url.pathname === "/api/v2/system/readiness") {
          return Response.json({
            schemaVersion: "2.4",
            status: "healthy",
            database: { healthy: true },
            eventStream: { status: "healthy" },
          });
        }
        if (method === "POST") {
          const body = JSON.parse(String(init?.body)) as {
            operatorToken: string;
          };
          expect(body.operatorToken).toBe(token);
          return Response.json({
            schemaVersion: "2.4",
            authenticated: true,
            actorId: "operator",
            expiresAt: "2099-01-01T00:00:00.000Z",
          }, {
            headers: {
              "set-cookie":
                "ti_scale_session=opaque-session; Path=/api/v2; HttpOnly; SameSite=Strict",
            },
          });
        }
        return Response.json(
          headers.get("Cookie")
            ? {
                schemaVersion: "2.4",
                configured: true,
                authenticated: true,
                actorId: "operator",
                expiresAt: "2099-01-01T00:00:00.000Z",
              }
            : {
                schemaVersion: "2.4",
                configured: true,
                authenticated: false,
              },
        );
      },
    });
    expect(await verifierInstance.verifyApplication()).toMatchObject({
      origin: "http://127.0.0.1:3132",
      liveness: "healthy",
      readiness: "healthy",
      authenticationConfigured: true,
      authenticatedRoundTrip: true,
      actorId: "operator",
    });
    expect(requests).toEqual([
      { path: "/api/v2/health", method: "GET", authenticated: false },
      {
        path: "/api/v2/system/readiness",
        method: "GET",
        authenticated: false,
      },
      {
        path: "/api/v2/auth/session",
        method: "GET",
        authenticated: false,
      },
      {
        path: "/api/v2/auth/session",
        method: "POST",
        authenticated: false,
      },
      {
        path: "/api/v2/auth/session",
        method: "GET",
        authenticated: true,
      },
    ]);
  });
});
