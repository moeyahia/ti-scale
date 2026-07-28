import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  chownSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  NMAP_ACTIVATION_BUNDLE_VERSION,
  NMAP_ACTIVATION_MUTATION_DISABLED_ERROR,
  NMAP_ACTIVATION_SERVICE_UNIT,
  NmapActivationBundleInstaller,
  type NmapActivationBundleDescriptor,
  type NmapActivationBundleInstallerOptions,
  type NmapActivationPostStartVerifier,
  type NmapBinaryIdentity,
  type ReviewedNmapInstallerPort,
  type TiScaleServiceController,
  type TiScaleServiceIdentity,
} from "../NmapActivationBundle";

const REPOSITORY_ROOT = join(import.meta.dir, "../../..");
const DESCRIPTOR_PATH = "deployment/runtime-config/nmap-activation-bundle.v1.json";
const EXACT_EXECUTABLE_PATH =
  "/opt/ti-scale-toolchain/nmap/5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f/nmap";
const EXACT_EXECUTABLE_SHA256 =
  "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f";
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), "ti-scale-nmap-policy-"));
  temporaryDirectories.push(path);
  return path;
}

function digest(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function binaryIdentity(): NmapBinaryIdentity {
  return {
    path: EXACT_EXECUTABLE_PATH,
    sha256: EXACT_EXECUTABLE_SHA256,
    uid: 0,
    gid: 0,
    mode: 0o555,
    fileCapabilities: "none",
    regularFile: true,
    symbolicLink: false,
  };
}

function activeServiceIdentity(): TiScaleServiceIdentity {
  return {
    id: NMAP_ACTIVATION_SERVICE_UNIT,
    loadState: "loaded",
    activeState: "active",
    mainPid: 4312,
    fragmentPath: "/etc/systemd/system/ti-scale.service",
  };
}

function mutationSentinelOptions(root: string, calls: string[]): NmapActivationBundleInstallerOptions {
  const fail = (name: string): never => {
    calls.push(name);
    throw new Error(`${name} must not be called`);
  };
  return {
    sourceRoot: join(root, "missing-source"),
    descriptorSha256: "0".repeat(64),
    installedGroupGid: 0,
    bundleInstallRoot: join(root, "must-not-create-bundles"),
    dropInDirectory: join(root, "must-not-create-drop-ins"),
    readActiveWork: () => fail("read-active-work"),
    nmapInstaller: {
      install: async () => fail("nmap-install"),
      verify: async () => fail("nmap-verify"),
    },
    service: {
      identity: async () => fail("service-identity"),
      stop: async () => fail("service-stop"),
      daemonReload: async () => fail("service-daemon-reload"),
      start: async () => fail("service-start"),
    },
    postStartVerifier: {
      verifyActivated: async () => fail("post-start-activated"),
      verifyPriorServiceHealthy: async () => fail("post-start-prior"),
    },
  };
}

function stageVerifiedFixture(): {
  readonly installer: NmapActivationBundleInstaller;
  readonly calls: string[];
} {
  const root = temporaryDirectory();
  chmodSync(root, 0o755);
  const sourceRoot = join(root, "source");
  mkdirSync(sourceRoot, { mode: 0o755 });
  const descriptorSource = join(REPOSITORY_ROOT, DESCRIPTOR_PATH);
  const descriptor = JSON.parse(
    readFileSync(descriptorSource, "utf8"),
  ) as NmapActivationBundleDescriptor;
  const sourceFiles = [
    DESCRIPTOR_PATH,
    ...descriptor.documents.map(({ sourcePath }) => sourcePath),
    descriptor.dropIn.sourcePath,
    descriptor.nmap.installerPath,
  ];
  for (const relativePath of sourceFiles) {
    const source = join(REPOSITORY_ROOT, relativePath);
    const destination = join(sourceRoot, relativePath);
    mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
    copyFileSync(source, destination);
    chownSync(destination, 0, 0);
    chmodSync(destination, readFileSync(source).length === 0
      ? 0o644
      : (relativePath === descriptor.nmap.installerPath ? descriptor.nmap.installerMode : 0o644));
  }

  const bundleInstallRoot = join(root, "installed-bundles");
  const bundleDirectory = join(bundleInstallRoot, descriptor.bundleVersion);
  mkdirSync(bundleDirectory, { recursive: true, mode: 0o750 });
  chownSync(bundleInstallRoot, 0, 0);
  chownSync(bundleDirectory, 0, 0);
  chmodSync(bundleInstallRoot, 0o750);
  chmodSync(bundleDirectory, 0o750);
  for (const document of descriptor.documents) {
    const destination = join(bundleDirectory, document.installName);
    copyFileSync(join(sourceRoot, document.sourcePath), destination);
    chownSync(destination, 0, 0);
    chmodSync(destination, document.installMode);
  }

  const dropInDirectory = join(root, "systemd", "ti-scale.service.d");
  mkdirSync(dropInDirectory, { recursive: true, mode: 0o755 });
  chownSync(dropInDirectory, 0, 0);
  chmodSync(dropInDirectory, 0o755);
  const dropInPath = join(dropInDirectory, descriptor.dropInName);
  copyFileSync(join(sourceRoot, descriptor.dropIn.sourcePath), dropInPath);
  chownSync(dropInPath, 0, 0);
  chmodSync(dropInPath, descriptor.dropIn.installMode);

  const calls: string[] = [];
  const nmapInstaller: ReviewedNmapInstallerPort = {
    install: async () => {
      calls.push("nmap-install");
      throw new Error("verify must not install");
    },
    verify: async () => {
      calls.push("nmap-verify");
      return binaryIdentity();
    },
  };
  const service: TiScaleServiceController = {
    identity: async () => {
      calls.push("service-identity");
      return activeServiceIdentity();
    },
    stop: async () => {
      calls.push("service-stop");
      throw new Error("verify must not stop");
    },
    daemonReload: async () => {
      calls.push("service-daemon-reload");
      throw new Error("verify must not reload");
    },
    start: async () => {
      calls.push("service-start");
      throw new Error("verify must not start");
    },
  };
  const postStartVerifier: NmapActivationPostStartVerifier = {
    verifyActivated: async () => {
      calls.push("post-start-activated");
    },
    verifyPriorServiceHealthy: async () => {
      calls.push("post-start-prior");
    },
  };
  return {
    calls,
    installer: new NmapActivationBundleInstaller({
      sourceRoot,
      descriptorSha256: digest(readFileSync(join(sourceRoot, DESCRIPTOR_PATH))),
      installedGroupGid: 0,
      bundleInstallRoot,
      dropInDirectory,
      readActiveWork: () => {
        calls.push("read-active-work");
        return { activeRuns: [], activeLeases: [] };
      },
      nmapInstaller,
      service,
      postStartVerifier,
    }),
  };
}

describe("reviewed Nmap activation no-backup boundary", () => {
  test.each(["install", "rollback"] as const)(
    "rejects direct %s before path, service, installer, or active-work access",
    async (operation) => {
      const root = temporaryDirectory();
      const calls: string[] = [];
      const options = mutationSentinelOptions(root, calls);
      const installer = new NmapActivationBundleInstaller(options);

      await expect(installer[operation]()).rejects.toThrow(
        NMAP_ACTIVATION_MUTATION_DISABLED_ERROR,
      );

      expect(calls).toEqual([]);
      expect(existsSync(options.sourceRoot)).toBe(false);
      expect(existsSync(options.bundleInstallRoot!)).toBe(false);
      expect(existsSync(options.dropInDirectory!)).toBe(false);
    },
  );

  test("keeps exact read-only verification operational without service mutation", async () => {
    const setup = stageVerifiedFixture();

    const result = await setup.installer.verify();

    expect(result).toMatchObject({
      bundleVersion: NMAP_ACTIVATION_BUNDLE_VERSION,
      status: "activated",
      controlsOnly: "ti-scale.service",
    });
    expect(setup.calls).toEqual([
      "nmap-verify",
      "service-identity",
      "post-start-activated",
    ]);
  });

  test.each(["install", "rollback"])(
    "keeps the %s CLI mutation path disabled",
    (operation) => {
      const result = Bun.spawnSync([
        process.execPath,
        join(REPOSITORY_ROOT, "scripts/install-reviewed-nmap-activation.ts"),
        operation,
        "--execute",
        "--confirm",
        NMAP_ACTIVATION_BUNDLE_VERSION,
      ], {
        cwd: REPOSITORY_ROOT,
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout.toString()).toBe("");
      expect(result.stderr.toString()).toContain("No-backup policy permits only:");
      expect(result.stderr.toString()).not.toContain("activated:");
    },
  );
});
