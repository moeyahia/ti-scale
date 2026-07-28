import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  attestInstalledReleaseServiceStartAdmission,
  buildReleaseServiceStartAdmissionBundle,
  buildReleaseServiceWrapperBundle,
  RELEASE_SERVICE_START_ADMISSION_BUN_PATH,
  RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND,
  RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
  RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT,
  RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND,
  releaseServiceStartAdmissionSelfReportMatches,
  serviceStartAdmissionConfigured,
  serviceStartAdmissionMountConfigured,
  serviceWrapperConfigured,
  serviceWrapperIdentityConfigured,
} from "../../../scripts/release/ReleaseServiceStartAdmissionBundle";
import { releaseServiceStartAdmissionSelfReport } from "../../../scripts/release/service-start-admission";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("stable release-start admission bundle", () => {
  test("builds one deterministic self-contained helper", async () => {
    const first = await buildReleaseServiceStartAdmissionBundle();
    const second = await buildReleaseServiceStartAdmissionBundle();
    expect(first.sha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(first.sha256).toBe(second.sha256);
    expect(first.bytes).toEqual(second.bytes);
    expect(first.bytes.byteLength).toBeGreaterThan(10_000);
  });

  test("builds one deterministic self-contained service wrapper", async () => {
    const first = await buildReleaseServiceWrapperBundle();
    const second = await buildReleaseServiceWrapperBundle();
    expect(first.sha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(first.sha256).toBe(second.sha256);
    expect(first.bytes).toEqual(second.bytes);
    expect(first.bytes.byteLength).toBeGreaterThan(5_000);
  });

  test("accepts only the exact effective non-ignored systemd command", () => {
    expect(serviceStartAdmissionConfigured(
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; ignore_errors=no ; }`,
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; flags=privileged ; }`,
    )).toBe(true);
    expect(serviceStartAdmissionConfigured(
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; ignore_errors=yes ; }`,
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; flags=privileged ; }`,
    )).toBe(false);
    expect(serviceStartAdmissionConfigured(
      `{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no ; } ` +
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; ignore_errors=no ; }`,
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; flags=privileged ; }`,
    )).toBe(false);
    expect(serviceStartAdmissionConfigured(
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; ignore_errors=no ; }`,
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_START_ADMISSION_EFFECTIVE_COMMAND} ; flags=none ; }`,
    )).toBe(false);
  });

  test("requires the exact helper protocol self-report", () => {
    expect(releaseServiceStartAdmissionSelfReportMatches(
      JSON.stringify(releaseServiceStartAdmissionSelfReport()),
    )).toBe(true);
    expect(releaseServiceStartAdmissionSelfReportMatches(JSON.stringify({
      ...releaseServiceStartAdmissionSelfReport(),
      authorizationSchema: "obsolete",
    }))).toBe(false);
    expect(releaseServiceStartAdmissionSelfReportMatches("not-json")).toBe(false);
  });

  test("requires the effective canonical release-journal mount dependency", () => {
    expect(serviceStartAdmissionMountConfigured(
      `/var/lib/ti-scale ${RELEASE_SERVICE_START_ADMISSION_TRANSACTION_ROOT}`,
    )).toBe(true);
    expect(serviceStartAdmissionMountConfigured("/var/lib/ti-scale")).toBe(false);
    expect(serviceStartAdmissionMountConfigured("")).toBe(false);
  });

  test("accepts only the exact unprivileged stable ExecStart wrapper", () => {
    const legacy = `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND} ; ignore_errors=no ; }`;
    expect(serviceWrapperConfigured(legacy,
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND} ; flags= ; }`,
    )).toBe(true);
    expect(serviceWrapperConfigured(legacy,
      `{ path=${RELEASE_SERVICE_START_ADMISSION_BUN_PATH} ; ` +
      `argv[]=${RELEASE_SERVICE_WRAPPER_EFFECTIVE_COMMAND} ; flags=privileged ; }`,
    )).toBe(false);
    expect(serviceWrapperConfigured(
      `{ path=/usr/local/bin/bun ; argv[]=/usr/local/bin/bun run server ; ignore_errors=no ; }`,
      `{ path=/usr/local/bin/bun ; argv[]=/usr/local/bin/bun run server ; flags= ; }`,
    )).toBe(false);
  });

  test("requires the exact non-root service identity and application root", () => {
    expect(serviceWrapperIdentityConfigured("ti-scale\n", "ti-scale\n", "/opt/ti-scale\n", "no\n"))
      .toBe(true);
    expect(serviceWrapperIdentityConfigured("root", "ti-scale", "/opt/ti-scale", "no")).toBe(false);
    expect(serviceWrapperIdentityConfigured("ti-scale", "root", "/opt/ti-scale", "no")).toBe(false);
    expect(serviceWrapperIdentityConfigured("ti-scale", "ti-scale", "/tmp/other", "no")).toBe(false);
    expect(serviceWrapperIdentityConfigured("ti-scale", "ti-scale", "/opt/ti-scale", "yes")).toBe(false);
  });

  test("attests exact bytes, modes, ownership, and reviewed drop-in", async () => {
    const workspace = mkdtempSync(join(tmpdir(), "ti-scale-start-helper-attestation-"));
    roots.push(workspace);
    chmodSync(workspace, 0o700);
    const helperPath = join(workspace, "libexec", "helper.js");
    const wrapperPath = join(workspace, "libexec", "wrapper.js");
    const dropInPath = join(workspace, "systemd", "10-release-start-admission.conf");
    const bunPath = join(workspace, "bin", "bun");
    for (const directory of [join(workspace, "libexec"), join(workspace, "systemd"), join(workspace, "bin")]) {
      mkdirSync(directory, { mode: 0o755 });
    }
    const bundle = await buildReleaseServiceStartAdmissionBundle();
    const wrapperBundle = await buildReleaseServiceWrapperBundle();
    writeFileSync(helperPath, bundle.bytes, { mode: 0o755 });
    writeFileSync(wrapperPath, wrapperBundle.bytes, { mode: 0o755 });
    writeFileSync(
      dropInPath,
      readFileSync("deployment/systemd/ti-scale.service.d/10-release-start-admission.conf"),
      { mode: 0o644 },
    );
    writeFileSync(bunPath, "reviewed interpreter fixture\n", { mode: 0o755 });

    const options = {
      helperPath,
      wrapperPath,
      dropInPath,
      bunPath,
      trustedAncestorBoundary: workspace,
      expectedUid: process.getuid?.() ?? 0,
      expectedGid: process.getgid?.() ?? 0,
    } as const;
    const receipt = await attestInstalledReleaseServiceStartAdmission(options);
    expect(receipt.helperSha256).toBe(bundle.sha256);
    expect(receipt.wrapperSha256).toBe(wrapperBundle.sha256);

    writeFileSync(helperPath, "tampered\n", { mode: 0o755 });
    await expect(attestInstalledReleaseServiceStartAdmission(options))
      .rejects.toThrow("does not match the current reviewed source bundle");

    writeFileSync(helperPath, bundle.bytes, { mode: 0o755 });
    writeFileSync(wrapperPath, "tampered\n", { mode: 0o755 });
    await expect(attestInstalledReleaseServiceStartAdmission(options))
      .rejects.toThrow("Installed service wrapper does not match");
  });
});
