import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT,
  REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT,
  loadProductionLocalGuidedToolConfiguration,
} from "../../../server/app/LocalGuidedToolConfiguration";
import {
  REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION,
  REVIEWED_WEB_ASSESSMENT_DESCRIPTOR_SHA256,
  REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME,
  ReviewedWebAssessmentActivationInstaller,
  loadReviewedWebAssessmentActivationBundle,
} from "../ReviewedWebAssessmentActivationBundle";
import { parseReviewedWebAssessmentActivationArguments } from "../../install-reviewed-web-assessment-activation";

const REPOSITORY_ROOT = join(import.meta.dir, "../../..");
const DESCRIPTOR = "deployment/runtime-config/reviewed-web-assessment-activation-bundle.v1.json";
const ENVIRONMENT = "deployment/runtime-config/reviewed-web-assessment-activation-environment.v1.conf";
const DROP_IN = "deployment/systemd/ti-scale.service.d/70-reviewed-web-assessment.conf";
const BASELINE_FILES = [
  "local-tool-capabilities.v1.json",
  "bubblewrap-probe-sandbox.v1.json",
  "engagement-workspace-mappings.v1.json",
] as const;
const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function digest(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function temporaryRoot(prefix: string, mode = 0o755): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(root, mode);
  temporaryRoots.push(root);
  return root;
}

function copiedSource(): string {
  const root = temporaryRoot("ti-scale-web-activation-source-");
  for (const path of [DESCRIPTOR, ENVIRONMENT, DROP_IN]) {
    const destination = join(root, path);
    mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
    copyFileSync(join(REPOSITORY_ROOT, path), destination);
    chmodSync(destination, 0o644);
  }
  return root;
}

function fixture(input: Readonly<{ readonly priorDropIn?: string }> = {}) {
  const root = temporaryRoot("ti-scale-web-activation-install-");
  const bundleRoot = join(root, "etc", "ti-scale", "runtime", "bundles");
  const dropInRoot = join(root, "etc", "systemd", "system", "ti-scale.service.d");
  const unrelatedRoot = join(root, "etc", "systemd", "system", "chillspwn.service.d");
  mkdirSync(bundleRoot, { recursive: true, mode: 0o750 });
  mkdirSync(dropInRoot, { recursive: true, mode: 0o755 });
  mkdirSync(unrelatedRoot, { recursive: true, mode: 0o755 });
  chmodSync(bundleRoot, 0o750);
  chmodSync(dropInRoot, 0o755);
  chmodSync(unrelatedRoot, 0o755);
  const unrelatedSentinel = join(unrelatedRoot, "sentinel.conf");
  writeFileSync(unrelatedSentinel, "unchanged\n", { mode: 0o644 });
  const installedDropIn = join(dropInRoot, REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME);
  if (input.priorDropIn !== undefined) {
    writeFileSync(installedDropIn, input.priorDropIn, { mode: 0o644 });
    chmodSync(installedDropIn, 0o644);
  }
  const installer = new ReviewedWebAssessmentActivationInstaller({
    sourceRoot: REPOSITORY_ROOT,
    installedGroupGid: process.getgid?.() ?? 0,
    bundleInstallRoot: bundleRoot,
    dropInDirectory: dropInRoot,
    clock: () => new Date("2026-07-20T10:00:00.000Z"),
  });
  return { root, bundleRoot, dropInRoot, unrelatedSentinel, installedDropIn, installer };
}

function localConfigurationEnvironment(): Readonly<Record<string, string>> {
  const root = temporaryRoot("ti-scale-web-config-loader-", 0o700);
  const values: Record<string, string> = {};
  const config = BASELINE_FILES.map((name) => {
    const bytes = readFileSync(join(REPOSITORY_ROOT, "deployment", "runtime-config", name));
    const path = join(root, name);
    writeFileSync(path, bytes, { mode: 0o600 });
    return { name, path, sha256: digest(bytes) };
  });
  const [manifest, sandbox, workspaces] = config;
  values[LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.trustRoot] = root;
  values[LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestPath] = manifest!.path;
  values[LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestSha256] = manifest!.sha256;
  values[LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxPath] = sandbox!.path;
  values[LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxSha256] = sandbox!.sha256;
  values[LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsPath] = workspaces!.path;
  values[LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsSha256] = workspaces!.sha256;
  const environmentLine = readFileSync(join(REPOSITORY_ROOT, ENVIRONMENT), "utf8").trim();
  const separator = environmentLine.indexOf("=");
  values[environmentLine.slice(0, separator)] = environmentLine.slice(separator + 1);
  return values;
}

describe("reviewed web-assessment production activation artifact", () => {
  test("the root CLI is read-only under the operator no-backup policy", () => {
    expect(parseReviewedWebAssessmentActivationArguments(["source-verify"]))
      .toEqual({ operation: "source-verify", mutates: false });
    expect(parseReviewedWebAssessmentActivationArguments(["verify-installed"]))
      .toEqual({ operation: "verify-installed", mutates: false });
    expect(() => parseReviewedWebAssessmentActivationArguments(["install"]))
      .toThrow("Mutation is disabled");
    expect(() => parseReviewedWebAssessmentActivationArguments([
      "rollback", "--execute", "--confirm", "wrong-version",
    ])).toThrow("Mutation is disabled");
    expect(() => parseReviewedWebAssessmentActivationArguments([
      "verify-installed", "--execute",
    ])).toThrow("accepts no additional arguments");
  });

  test("pins one Ti-Scale-only feature flag and one exact versioned service drop-in", () => {
    const bundle = loadReviewedWebAssessmentActivationBundle(REPOSITORY_ROOT);
    expect(digest(bundle.descriptorBytes)).toBe(REVIEWED_WEB_ASSESSMENT_DESCRIPTOR_SHA256);
    expect(bundle.descriptor).toMatchObject({
      bundleVersion: REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION,
      serviceUnit: "ti-scale.service",
      dropInName: REVIEWED_WEB_ASSESSMENT_DROP_IN_NAME,
    });
    expect(bundle.environmentBytes.toString("utf8")).toBe(
      "TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED=true\n",
    );
    expect(bundle.dropInBytes.toString("utf8")).toBe([
      "[Service]",
      `EnvironmentFile=/etc/ti-scale/runtime/bundles/${REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION}/activation-environment.v1.conf`,
      "",
    ].join("\n"));
  });

  test("the exact activation environment composes only the two reviewed web tools", () => {
    const loaded = loadProductionLocalGuidedToolConfiguration(localConfigurationEnvironment());
    expect(loaded.status).toBe("loaded");
    if (loaded.status !== "loaded") throw new Error("Reviewed local configuration did not load");
    expect(loaded.webAssessmentIncluded).toBeTrue();
    expect(loaded.manifest.descriptor.enabledToolCount).toBe(6);
    expect(loaded.manifest.list()
      .filter(({ toolId }) => toolId.includes("whatweb") || toolId.includes("ffuf"))
      .map(({ toolId }) => toolId)).toEqual([
        "kali:ffuf-bounded-content-discovery",
        "kali:whatweb-bounded-fingerprint",
      ]);
    expect(localConfigurationEnvironment()[REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT])
      .toBe("true");
  });

  test("installs an exact forward-only bundle without a persisted rollback payload", () => {
    const value = fixture();
    const before = readFileSync(value.unrelatedSentinel);
    expect(value.installer.installPendingRestart()).toMatchObject({
      status: "installed_pending_restart",
      serviceUnit: "ti-scale.service",
      serviceRestarted: false,
    });
    const bundleDirectory = join(value.bundleRoot, REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION);
    expect(readFileSync(join(bundleDirectory, "activation-environment.v1.conf"), "utf8"))
      .toBe("TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED=true\n");
    expect(lstatSync(join(bundleDirectory, "activation-environment.v1.conf")).mode & 0o7777)
      .toBe(0o440);
    expect(value.installer.verifyPendingRestart()).toMatchObject({
      status: "verified_pending_restart",
      serviceRestarted: false,
    });
    expect(existsSync(join(bundleDirectory, "rollback-receipt.v1.json"))).toBeFalse();
    expect(() => value.installer.rollbackPendingRestart())
      .toThrow("rollback is disabled");
    expect(existsSync(bundleDirectory)).toBeTrue();
    expect(existsSync(value.installedDropIn)).toBeTrue();
    expect(readFileSync(value.unrelatedSentinel)).toEqual(before);
  });

  test("does not persist a prior Ti-Scale drop-in for later rollback", () => {
    const prior = "[Service]\nEnvironment=TI_SCALE_PRIOR_TEST_VALUE=retained\n";
    const value = fixture({ priorDropIn: prior });
    value.installer.installPendingRestart();
    expect(readFileSync(value.installedDropIn, "utf8")).not.toBe(prior);
    expect(existsSync(join(
      value.bundleRoot,
      REVIEWED_WEB_ASSESSMENT_ACTIVATION_VERSION,
      "rollback-receipt.v1.json",
    ))).toBeFalse();
    expect(() => value.installer.rollbackPendingRestart())
      .toThrow("rollback is disabled");
  });

  test("fails closed on source drift and installed config drift", () => {
    const sourceRoot = copiedSource();
    writeFileSync(join(sourceRoot, ENVIRONMENT), "TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED=false\n");
    expect(() => loadReviewedWebAssessmentActivationBundle(sourceRoot))
      .toThrow("failed SHA-256 verification");

    const value = fixture();
    value.installer.installPendingRestart();
    writeFileSync(value.installedDropIn, "[Service]\nEnvironment=TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED=false\n");
    chmodSync(value.installedDropIn, 0o644);
    expect(() => value.installer.verifyPendingRestart())
      .toThrow("failed exact identity verification");
  });
});
