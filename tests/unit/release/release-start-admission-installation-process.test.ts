import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildReleaseServiceStartAdmissionBundle,
  buildReleaseServiceWrapperBundle,
} from "../../../scripts/release/ReleaseServiceStartAdmissionBundle";
import {
  assertReleaseServiceStartAdmissionJournalReadableByService,
  assertReleaseServiceStartAdmissionInstallationCommitted,
  prepareReleaseServiceStartAdmissionTransactionRoot,
  RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME,
  type ReleaseServiceStartAdmissionAccessCommandRunner,
  type ReleaseServiceStartAdmissionInPlaceWritePhase,
  type ReleaseServiceStartAdmissionInstalledArtifact,
  type ReleaseServiceStartAdmissionInstallationBoundary,
} from "../../../scripts/release/ReleaseServiceStartAdmissionInstallation";

interface Fixture {
  readonly root: string;
  readonly configurationPath: string;
  readonly resultPath: string;
  readonly reloadReceiptPath: string;
  readonly transactionRoot: string;
  readonly journalPath: string;
  readonly helperPath: string;
  readonly wrapperPath: string;
  readonly dropInPath: string;
  readonly helperInputPath: string;
  readonly wrapperInputPath: string;
  readonly dropInInputPath: string;
  readonly expectedHelperBytes: Uint8Array;
  readonly expectedWrapperBytes: Uint8Array;
  readonly expectedDropInBytes: Uint8Array;
  readonly applicationStartedPath: string;
  readonly expectedUid: number;
  readonly expectedGid: number;
}

interface InstallationJournal {
  readonly phase: string;
  readonly installationId: string;
  readonly wrapper: { readonly sha256: string };
  readonly helper: { readonly sha256: string };
  readonly dropIn: { readonly sha256: string };
}

const workerPath = join(
  process.cwd(),
  "tests/unit/release/fixtures/release-start-admission-installation-worker.ts",
);
const temporaryRoots: string[] = [];
let helperBytes = new Uint8Array();
let wrapperBytes = new Uint8Array();
let dropInBytes = new Uint8Array();

const boundaries: readonly ReleaseServiceStartAdmissionInstallationBoundary[] = [
  "wrapper_guard_written",
  "journal_prepared",
  "helper_written",
  "helper_recorded",
  "drop_in_written",
  "drop_in_recorded",
  "files_written",
  "activation_started",
  "service_manager_reloaded",
  "activation_verified",
  "committed",
];

beforeAll(async () => {
  helperBytes = (await buildReleaseServiceStartAdmissionBundle()).bytes;
  wrapperBytes = (await buildReleaseServiceWrapperBundle()).bytes;
  dropInBytes = readFileSync(
    "deployment/systemd/ti-scale.service.d/10-release-start-admission.conf",
  );
});

afterAll(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function setup(boundary: ReleaseServiceStartAdmissionInstallationBoundary): Fixture {
  const root = mkdtempSync(join(tmpdir(), `ti-scale-admission-install-${boundary}-`));
  temporaryRoots.push(root);
  chmodSync(root, 0o700);
  const transactionRoot = join(root, "release-transactions");
  const targets = join(root, "targets");
  const inputs = join(root, "inputs");
  mkdirSync(transactionRoot, { mode: 0o755 });
  mkdirSync(join(targets, "libexec"), { recursive: true, mode: 0o755 });
  mkdirSync(join(targets, "systemd"), { recursive: true, mode: 0o755 });
  mkdirSync(inputs, { mode: 0o700 });
  const helperPath = join(targets, "libexec", "helper.js");
  const wrapperPath = join(targets, "libexec", "wrapper.js");
  const dropInPath = join(targets, "systemd", "drop-in.conf");
  const helperInputPath = join(inputs, "helper.js");
  const wrapperInputPath = join(inputs, "wrapper.js");
  const dropInInputPath = join(inputs, "drop-in.conf");
  const expectedUid = process.getuid?.() ?? 0;
  const expectedGid = process.getgid?.() ?? 0;
  const resultPath = join(root, "result.json");
  const reloadReceiptPath = join(root, "service-manager-reloaded.json");
  const applicationRoot = join(root, "application");
  const applicationStartedPath = join(root, "application-started.json");
  mkdirSync(join(applicationRoot, "server"), { recursive: true, mode: 0o755 });
  writeFileSync(
    join(applicationRoot, "server", "index.ts"),
    `import { writeFileSync } from "node:fs";\n` +
      `writeFileSync(${JSON.stringify(applicationStartedPath)}, "started\\n");\n`,
    { mode: 0o600 },
  );
  const replaceInstalledPaths = (value: Uint8Array): Uint8Array => Buffer.from(
    Buffer.from(value).toString("utf8")
      .replaceAll("/var/lib/ti-scale/release-transactions", transactionRoot)
      .replaceAll(
        "/usr/local/libexec/ti-scale-release-start-admission.js",
        helperPath,
      )
      .replaceAll("/usr/local/libexec/ti-scale-service-wrapper.js", wrapperPath)
      .replaceAll(
        "/etc/systemd/system/ti-scale.service.d/10-release-start-admission.conf",
        dropInPath,
      )
      .replaceAll("/usr/local/bin/bun", process.execPath)
      .replaceAll("/opt/ti-scale", applicationRoot),
    "utf8",
  );
  const expectedHelperBytes = replaceInstalledPaths(helperBytes);
  const expectedWrapperBytes = replaceInstalledPaths(wrapperBytes);
  const expectedDropInBytes = replaceInstalledPaths(dropInBytes);
  writeFileSync(
    helperPath,
    "#!/usr/bin/env bun\nprocess.exit(0);\n",
    { mode: 0o755 },
  );
  writeFileSync(
    wrapperPath,
    `#!/usr/bin/env bun\n` +
      `import { writeFileSync } from "node:fs";\n` +
      `writeFileSync(${JSON.stringify(applicationStartedPath)}, "old-started\\n");\n`,
    { mode: 0o755 },
  );
  writeFileSync(dropInPath, "old drop-in\n", { mode: 0o644 });
  writeFileSync(helperInputPath, expectedHelperBytes, { mode: 0o600 });
  writeFileSync(wrapperInputPath, expectedWrapperBytes, { mode: 0o600 });
  writeFileSync(dropInInputPath, expectedDropInBytes, { mode: 0o600 });
  const configurationPath = join(root, "worker.json");
  writeFileSync(configurationPath, `${JSON.stringify({
    transactionRoot,
    trustedAncestorBoundary: root,
    helperPath,
    wrapperPath,
    dropInPath,
    helperInputPath,
    wrapperInputPath,
    dropInInputPath,
    resultPath,
    reloadReceiptPath,
    crashBoundary: boundary,
    expectedUid,
    expectedGid,
  }, null, 2)}\n`, { mode: 0o600 });
  return {
    root,
    configurationPath,
    resultPath,
    reloadReceiptPath,
    transactionRoot,
    journalPath: join(
      transactionRoot,
      RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME,
    ),
    helperPath,
    wrapperPath,
    dropInPath,
    helperInputPath,
    wrapperInputPath,
    dropInInputPath,
    expectedHelperBytes,
    expectedWrapperBytes,
    expectedDropInBytes,
    applicationStartedPath,
    expectedUid,
    expectedGid,
  };
}

async function runWorker(
  fixture: Fixture,
  crashBoundary: string,
  umask?: number,
): Promise<number> {
  const configuration = JSON.parse(
    readFileSync(fixture.configurationPath, "utf8"),
  ) as Record<string, unknown>;
  writeFileSync(fixture.configurationPath, `${JSON.stringify({
    ...configuration,
    crashBoundary,
    crashWriteArtifact: "none",
    crashWritePhase: "none",
    ...(umask === undefined ? {} : { umask }),
  }, null, 2)}\n`, { mode: 0o600 });
  rmSync(fixture.resultPath, { force: true });
  const child = Bun.spawn([
    process.execPath,
    "run",
    workerPath,
    fixture.configurationPath,
  ], {
    cwd: process.cwd(),
    stdout: "pipe",
    stderr: "pipe",
  });
  return child.exited;
}

async function runWorkerAtWritePhase(
  fixture: Fixture,
  artifact: ReleaseServiceStartAdmissionInstalledArtifact,
  phase: ReleaseServiceStartAdmissionInPlaceWritePhase,
): Promise<number> {
  const configuration = JSON.parse(
    readFileSync(fixture.configurationPath, "utf8"),
  ) as Record<string, unknown>;
  writeFileSync(fixture.configurationPath, `${JSON.stringify({
    ...configuration,
    crashBoundary: "none",
    crashWriteArtifact: artifact,
    crashWritePhase: phase,
  }, null, 2)}\n`, { mode: 0o600 });
  rmSync(fixture.resultPath, { force: true });
  const child = Bun.spawn([
    process.execPath,
    "run",
    workerPath,
    fixture.configurationPath,
  ], {
    cwd: process.cwd(),
    stdout: "pipe",
    stderr: "pipe",
  });
  return child.exited;
}

function installationOptions(fixture: Fixture) {
  return {
    transactionRoot: fixture.transactionRoot,
    trustedAncestorBoundary: fixture.root,
    helperPath: fixture.helperPath,
    wrapperPath: fixture.wrapperPath,
    dropInPath: fixture.dropInPath,
    expectedUid: fixture.expectedUid,
    expectedGid: fixture.expectedGid,
  } as const;
}

function installedCount(fixture: Fixture): number {
  return [
    [fixture.wrapperPath, fixture.expectedWrapperBytes],
    [fixture.helperPath, fixture.expectedHelperBytes],
    [fixture.dropInPath, fixture.expectedDropInBytes],
  ].filter(([path, bytes]) =>
    sha256(readFileSync(path as string)) === sha256(bytes as Uint8Array)
  ).length;
}

async function runInstalledEntrypoint(path: string): Promise<number> {
  const child = Bun.spawn([
    process.execPath,
    "run",
    path,
  ], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      INVOCATION_ID: "a".repeat(32),
      TI_SCALE_HOST: "127.0.0.1",
      TI_SCALE_PORT: "43199",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  return child.exited;
}

function assertContentFreeJournal(fixture: Fixture): InstallationJournal {
  const names = readdirSync(fixture.transactionRoot).sort();
  expect(names).toEqual([RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME]);
  const raw = readFileSync(fixture.journalPath, "utf8");
  expect(raw).not.toContain("old helper");
  expect(raw).not.toContain("old wrapper");
  expect(raw).not.toContain("import ");
  expect(raw).not.toContain("#!/usr/bin/env");
  const journal = JSON.parse(raw) as InstallationJournal;
  expect(Object.keys(journal).sort()).toEqual([
    "dropIn",
    "helper",
    "installationId",
    "phase",
    "recordSha256",
    "schemaVersion",
    "wrapper",
  ]);
  return journal;
}

function expectNoSiblingPayloadCopies(fixture: Fixture): void {
  expect(readdirSync(join(fixture.root, "targets", "libexec")).sort())
    .toEqual(["helper.js", "wrapper.js"]);
  expect(readdirSync(join(fixture.root, "targets", "systemd")).sort())
    .toEqual(["drop-in.conf"]);
  for (const name of readdirSync(fixture.transactionRoot)) {
    if (name === RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME) continue;
    const bytes = readFileSync(join(fixture.transactionRoot, name), "utf8");
    expect(bytes).not.toContain("#!/usr/bin/env");
    expect(bytes).not.toContain("import ");
  }
}

function traverseOnlyAccessRunner(
  fixture: Fixture,
): ReleaseServiceStartAdmissionAccessCommandRunner {
  let policyEnforced = false;
  return (command) => {
    if (command[0] === "/usr/bin/setfacl") {
      policyEnforced = true;
      return { exitCode: 0 };
    }
    const flag = command[5];
    const target = command[6];
    if (target === fixture.journalPath && flag === "-r") {
      return { exitCode: 0 };
    }
    return { exitCode: policyEnforced && flag === "-x" ? 0 : 1 };
  };
}

describe("release-start admission fixed-path installation boundaries", () => {
  for (const boundary of boundaries) {
    test(`SIGKILL at ${boundary} is fail-closed and repairs only forward`, async () => {
      const fixture = setup(boundary);
      expect(await runWorker(fixture, boundary)).not.toBe(0);
      expect(existsSync(fixture.resultPath)).toBe(false);
      const expectedInstalledCount =
        boundary === "wrapper_guard_written" || boundary === "journal_prepared"
        ? 1
        : boundary === "helper_written" || boundary === "helper_recorded"
        ? 2
        : 3;
      expect(installedCount(fixture)).toBe(expectedInstalledCount);
      expectNoSiblingPayloadCopies(fixture);
      const interrupted = boundary === "wrapper_guard_written"
        ? undefined
        : assertContentFreeJournal(fixture);

      if (boundary === "committed") {
        expect(interrupted?.phase).toBe("committed");
        expect(assertReleaseServiceStartAdmissionInstallationCommitted(
          installationOptions(fixture),
        ).phase).toBe("committed");
      } else {
        expect(interrupted?.phase).not.toBe("committed");
        expect(() => assertReleaseServiceStartAdmissionInstallationCommitted(
          installationOptions(fixture),
        )).toThrow("installation is incomplete");
        rmSync(fixture.applicationStartedPath, { force: true });
        expect(await runInstalledEntrypoint(fixture.wrapperPath)).not.toBe(0);
        expect(existsSync(fixture.applicationStartedPath)).toBe(false);
      }
      expect(existsSync(fixture.reloadReceiptPath)).toBe([
        "service_manager_reloaded",
        "activation_verified",
        "committed",
      ].includes(boundary));

      expect(await runWorker(fixture, "none")).toBe(0);
      expect(existsSync(fixture.resultPath)).toBe(true);
      const result = JSON.parse(readFileSync(fixture.resultPath, "utf8")) as {
        readonly phase: string;
        readonly status: string;
      };
      expect(result.phase).toBe("committed");
      expect(result.status).toBe(boundary === "committed"
        ? "already_installed"
        : "installed");
      expect(installedCount(fixture)).toBe(3);
      expect(lstatSync(fixture.wrapperPath).mode & 0o777).toBe(0o755);
      expect(lstatSync(fixture.helperPath).mode & 0o777).toBe(0o755);
      expect(lstatSync(fixture.dropInPath).mode & 0o777).toBe(0o644);
      expect(assertContentFreeJournal(fixture).phase).toBe("committed");
      expect(assertReleaseServiceStartAdmissionInstallationCommitted(
        installationOptions(fixture),
      ).phase).toBe("committed");
    }, 45_000);
  }

  for (const artifact of ["wrapper", "helper", "drop_in"] as const) {
    for (const phase of [
      "opened",
      "partial_written",
      "file_written",
      "file_synced",
      "directory_synced",
    ] as const) {
      test(`SIGKILL during ${artifact} ${phase} leaves no sibling payload copy`, async () => {
        const fixture = setup("wrapper_guard_written");
        expect(await runWorkerAtWritePhase(fixture, artifact, phase)).not.toBe(0);
        expect(existsSync(fixture.resultPath)).toBe(false);
        expectNoSiblingPayloadCopies(fixture);
        rmSync(fixture.applicationStartedPath, { force: true });
        await runInstalledEntrypoint(fixture.wrapperPath);
        expect(existsSync(fixture.applicationStartedPath)).toBe(false);

        expect(await runWorker(fixture, "none")).toBe(0);
        expect(installedCount(fixture)).toBe(3);
        expectNoSiblingPayloadCopies(fixture);
        expect(assertReleaseServiceStartAdmissionInstallationCommitted(
          installationOptions(fixture),
        ).phase).toBe("committed");
      }, 45_000);
    }
  }

  test("a fresh process may supersede a partial attempt only with a new forward write", async () => {
    const fixture = setup("helper_written");
    expect(await runWorker(fixture, "helper_written")).not.toBe(0);
    const first = assertContentFreeJournal(fixture);
    const nextHelper = Buffer.from("later reviewed helper\n");
    const nextWrapper = Buffer.from("later reviewed wrapper\n");
    const nextDropIn = Buffer.from("later reviewed drop-in\n");
    writeFileSync(fixture.helperInputPath, nextHelper, { mode: 0o600 });
    writeFileSync(fixture.wrapperInputPath, nextWrapper, { mode: 0o600 });
    writeFileSync(fixture.dropInInputPath, nextDropIn, { mode: 0o600 });

    expect(await runWorker(fixture, "none")).toBe(0);
    expect(readFileSync(fixture.helperPath)).toEqual(nextHelper);
    expect(readFileSync(fixture.wrapperPath)).toEqual(nextWrapper);
    expect(readFileSync(fixture.dropInPath)).toEqual(nextDropIn);
    const second = assertContentFreeJournal(fixture);
    expect(second.phase).toBe("committed");
    expect(second.installationId).not.toBe(first.installationId);
    expect(second.helper.sha256).toBe(sha256(nextHelper));
    expect(second.wrapper.sha256).toBe(sha256(nextWrapper));
    expect(second.dropIn.sha256).toBe(sha256(nextDropIn));
  }, 45_000);

  test("committed-state checks fail closed on live-file divergence", async () => {
    const fixture = setup("committed");
    expect(await runWorker(fixture, "none")).toBe(0);
    writeFileSync(fixture.wrapperPath, "tampered\n", { mode: 0o755 });
    expect(() => assertReleaseServiceStartAdmissionInstallationCommitted(
      installationOptions(fixture),
    )).toThrow("artifact does not match committed state");
    expect(assertContentFreeJournal(fixture).phase).toBe("committed");
  }, 45_000);

  test("the transaction root is canonicalized to traverse-only service access", async () => {
    const fixture = setup("committed");
    expect(await runWorker(fixture, "none")).toBe(0);
    chmodSync(fixture.transactionRoot, 0o700);
    let policyEnforced = false;
    const commands: Array<{
      readonly command: readonly string[];
      readonly purpose: string;
      readonly allowNonZeroExit: boolean;
    }> = [];
    const options = {
      ...installationOptions(fixture),
      serviceUser: "ti-scale",
      runServiceAccessCommand: (
        command: readonly string[],
        invocation: { readonly purpose: string; readonly allowNonZeroExit: boolean },
      ) => {
        commands.push({ command, ...invocation });
        if (command[0] === "/usr/bin/setfacl") {
          policyEnforced = true;
          return { exitCode: 0 };
        }
        const flag = command[5];
        const target = command[6];
        if (target === fixture.journalPath && flag === "-r") {
          return { exitCode: 0 };
        }
        return {
          exitCode: policyEnforced && flag === "-x" ? 0 : 1,
        };
      },
    } as const;

    prepareReleaseServiceStartAdmissionTransactionRoot(options);
    expect(
      assertReleaseServiceStartAdmissionJournalReadableByService(options).phase,
    ).toBe("committed");

    const rootMode = lstatSync(fixture.transactionRoot).mode & 0o777;
    expect(rootMode & 0o700).toBe(0o700);
    expect(rootMode & 0o067).toBe(0);
    expect(commands).toEqual([
      {
        command: [
          "/usr/bin/setfacl",
          "--remove-default",
          "--set",
          "user::rwx,user:ti-scale:--x,group::---,mask::--x,other::---",
          "--",
          fixture.transactionRoot,
        ],
        purpose: "enforce_traverse_only_acl",
        allowNonZeroExit: false,
      },
      {
        command: [
          "/usr/sbin/runuser",
          "--user",
          "ti-scale",
          "--",
          "/usr/bin/test",
          "-x",
          fixture.transactionRoot,
        ],
        purpose: "probe_traverse",
        allowNonZeroExit: true,
      },
      {
        command: [
          "/usr/sbin/runuser",
          "--user",
          "ti-scale",
          "--",
          "/usr/bin/test",
          "-r",
          fixture.transactionRoot,
        ],
        purpose: "probe_list",
        allowNonZeroExit: true,
      },
      {
        command: [
          "/usr/sbin/runuser",
          "--user",
          "ti-scale",
          "--",
          "/usr/bin/test",
          "-w",
          fixture.transactionRoot,
        ],
        purpose: "probe_write",
        allowNonZeroExit: true,
      },
      {
        command: [
          "/usr/sbin/runuser",
          "--user",
          "ti-scale",
          "--",
          "/usr/bin/test",
          "-r",
          fixture.journalPath,
        ],
        purpose: "probe_read",
        allowNonZeroExit: true,
      },
    ]);
    expect(assertReleaseServiceStartAdmissionInstallationCommitted(
      installationOptions(fixture),
    ).phase).toBe("committed");
    expect(readdirSync(fixture.transactionRoot)).toContain(
      RELEASE_SERVICE_START_ADMISSION_INSTALLATION_JOURNAL_NAME,
    );
  }, 45_000);

  test("service access configuration requires a valid user and runner pair", () => {
    const fixture = setup("committed");
    expect(() => prepareReleaseServiceStartAdmissionTransactionRoot({
      ...installationOptions(fixture),
      serviceUser: "ti-scale",
    })).toThrow("requires both a service user and an access-command runner");
    expect(() => prepareReleaseServiceStartAdmissionTransactionRoot({
      ...installationOptions(fixture),
      runServiceAccessCommand: () => ({ exitCode: 0 }),
    })).toThrow("requires both a service user and an access-command runner");
    expect(() => prepareReleaseServiceStartAdmissionTransactionRoot({
      ...installationOptions(fixture),
      serviceUser: "../ti-scale",
      runServiceAccessCommand: () => ({ exitCode: 0 }),
    })).toThrow("service user is malformed");
  });

  test("ACL enforcement failure stops installation before any access claim", () => {
    const fixture = setup("committed");
    expect(() => prepareReleaseServiceStartAdmissionTransactionRoot({
      ...installationOptions(fixture),
      serviceUser: "ti-scale",
      runServiceAccessCommand: () => ({ exitCode: 1 }),
    })).toThrow("failed during enforce_traverse_only_acl");
  });

  test("failed traversal proof stops installation after ACL enforcement", () => {
    const fixture = setup("committed");
    expect(() => prepareReleaseServiceStartAdmissionTransactionRoot({
      ...installationOptions(fixture),
      serviceUser: "ti-scale",
      runServiceAccessCommand: (command) => ({
        exitCode: command[0] === "/usr/bin/setfacl" ? 0 : 1,
      }),
    })).toThrow("root remains inaccessible to the service user");
  });

  for (const excessiveFlag of ["-r", "-w"] as const) {
    test(`service ${excessiveFlag} access to the root is rejected as excessive`, () => {
      const fixture = setup("committed");
      expect(() => prepareReleaseServiceStartAdmissionTransactionRoot({
        ...installationOptions(fixture),
        serviceUser: "ti-scale",
        runServiceAccessCommand: (command) => {
          if (command[0] === "/usr/bin/setfacl") return { exitCode: 0 };
          const flag = command[5];
          return {
            exitCode: flag === "-x" || flag === excessiveFlag ? 0 : 1,
          };
        },
      })).toThrow("root grants excessive service-user access");
    });
  }

  test("an inode replacement during ACL enforcement is rejected", () => {
    const fixture = setup("committed");
    const displacedRoot = `${fixture.transactionRoot}.displaced`;
    let replaced = false;
    expect(() => prepareReleaseServiceStartAdmissionTransactionRoot({
      ...installationOptions(fixture),
      serviceUser: "ti-scale",
      runServiceAccessCommand: (command) => {
        if (command[0] === "/usr/bin/setfacl" && !replaced) {
          replaced = true;
          renameSync(fixture.transactionRoot, displacedRoot);
          mkdirSync(fixture.transactionRoot, { mode: 0o700 });
          return { exitCode: 0 };
        }
        return { exitCode: command[5] === "-x" ? 0 : 1 };
      },
    })).toThrow("directory inode is not trusted");
  });

  test("ACL canonicalization preserves trusted directory special bits", () => {
    const fixture = setup("committed");
    const chmod = Bun.spawnSync([
      "/usr/bin/chmod",
      "1700",
      fixture.transactionRoot,
    ]);
    expect(chmod.exitCode).toBe(0);
    expect(lstatSync(fixture.transactionRoot).mode & 0o7000).toBe(0o1000);
    prepareReleaseServiceStartAdmissionTransactionRoot({
      ...installationOptions(fixture),
      serviceUser: "ti-scale",
      runServiceAccessCommand: traverseOnlyAccessRunner(fixture),
    });
    expect(lstatSync(fixture.transactionRoot).mode & 0o7000).toBe(0o1000);
  });

  test("a committed journal that the service cannot read fails closed", async () => {
    const fixture = setup("committed");
    expect(await runWorker(fixture, "none")).toBe(0);
    expect(() => assertReleaseServiceStartAdmissionJournalReadableByService({
      ...installationOptions(fixture),
      serviceUser: "ti-scale",
      runServiceAccessCommand: () => ({ exitCode: 1 }),
    })).toThrow("journal is unreadable to the service user");
  }, 45_000);

  test("a restrictive installer umask cannot make the journal root-only", async () => {
    const fixture = setup("committed");
    expect(await runWorker(fixture, "none", 0o077)).toBe(0);
    expect(lstatSync(fixture.journalPath).mode & 0o777).toBe(0o644);
    expect(assertContentFreeJournal(fixture).phase).toBe("committed");
    expect(assertReleaseServiceStartAdmissionInstallationCommitted(
      installationOptions(fixture),
    ).phase).toBe("committed");
  }, 45_000);

  test("a restrictive-umask interruption retries to a readable committed journal", async () => {
    const fixture = setup("journal_prepared");
    expect(await runWorker(fixture, "journal_prepared", 0o077)).not.toBe(0);
    expect(lstatSync(fixture.journalPath).mode & 0o777).toBe(0o644);
    expect(await runWorker(fixture, "none", 0o077)).toBe(0);
    expect(lstatSync(fixture.journalPath).mode & 0o777).toBe(0o644);
    expect(assertReleaseServiceStartAdmissionInstallationCommitted(
      installationOptions(fixture),
    ).phase).toBe("committed");
  }, 45_000);

  test("the first wrapper write closes the old-helper startup race before a journal exists", async () => {
    const fixture = setup("wrapper_guard_written");
    expect(await runInstalledEntrypoint(fixture.helperPath)).toBe(0);
    expect(await runInstalledEntrypoint(fixture.wrapperPath)).toBe(0);
    expect(readFileSync(fixture.applicationStartedPath, "utf8")).toBe("old-started\n");
    rmSync(fixture.applicationStartedPath);

    expect(await runWorker(fixture, "wrapper_guard_written")).not.toBe(0);
    expect(existsSync(fixture.journalPath)).toBe(false);
    expect(await runInstalledEntrypoint(fixture.helperPath)).toBe(0);
    expect(await runInstalledEntrypoint(fixture.wrapperPath)).not.toBe(0);
    expect(existsSync(fixture.applicationStartedPath)).toBe(false);

    expect(await runWorker(fixture, "none")).toBe(0);
    expect(await runInstalledEntrypoint(fixture.helperPath)).toBe(0);
    expect(await runInstalledEntrypoint(fixture.wrapperPath)).toBe(0);
    expect(readFileSync(fixture.applicationStartedPath, "utf8")).toBe("started\n");
  }, 45_000);
});
