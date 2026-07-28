import { describe, expect, test } from "bun:test";
import { readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";

const SCRIPT = new URL("../../../scripts/install-reviewed-nmap.sh", import.meta.url);
const MANIFEST = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const DOCUMENTATION = new URL("../../../docs/reviewed-nmap-capability.md", import.meta.url);
const EXPECTED_SHA256 = "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f";

describe("reviewed nmap installer", () => {
  test("pins one capability-free executable identity and passes shell syntax validation", () => {
    const script = readFileSync(SCRIPT, "utf8");
    const syntax = spawnSync("/usr/bin/bash", ["-n", SCRIPT.pathname], {
      encoding: "utf8",
      shell: false,
    });
    expect(syntax.status).toBe(0);
    expect(syntax.stderr).toBe("");
    expect(script).toContain(`EXPECTED_SHA256="${EXPECTED_SHA256}"`);
    expect(script).toContain('SOURCE_EXECUTABLE="/usr/lib/nmap/nmap"');
    expect(script).toContain('INSTALL_ROOT="/opt/ti-scale-toolchain/nmap"');
    expect(script).toMatch(/for command_name in awk /u);
    expect(script).toContain("install -o root -g root -m 0555");
    expect(script).toContain("getcap -n --");
    expect(script).toContain("--no-new-privs");
    expect(script).toContain("--bounding-set=-all");
    expect(script).toContain('ln -- "${stage_directory}/nmap" "${DESTINATION_EXECUTABLE}"');
    expect(script).not.toMatch(/\bsetcap\b/u);
    expect(script).not.toMatch(/\b(?:eval|sh -c|bash -c)\b/u);
    expect(script).not.toContain("/etc/");
    expect(statSync(SCRIPT).mode & 0o111).not.toBe(0);
  });

  test("matches the disabled manifest binding and documents forward-only maintenance", () => {
    const manifest = JSON.parse(readFileSync(MANIFEST, "utf8")) as {
      tools: Array<Record<string, any>>;
    };
    const nmap = manifest.tools.find(({ toolId }) =>
      toolId === "kali:nmap-tcp-connect-service-scan");
    expect(nmap).toMatchObject({
      activation: "disabled",
      executable: {
        path: `/opt/ti-scale-toolchain/nmap/${EXPECTED_SHA256}/nmap`,
        expectedSha256: EXPECTED_SHA256,
        fileCapabilities: "none",
      },
      execution: {
        shell: false,
        noNewPrivilegesRequired: true,
        filesystemWritePolicy: "resolved_workspace_only",
        timeoutMs: 150_000,
        maximumOutputBytes: 2_097_152,
      },
      actionClassIds: ["port_service_enumeration"],
    });
    const documentation = readFileSync(DOCUMENTATION, "utf8");
    expect(documentation).toContain("forward-only, no-backup");
    expect(documentation).toContain(
      "There is no public rollback or backup path.",
    );
    expect(documentation).toContain(
      "`install`, `rollback`,\n`--execute`, and `--confirm` are rejected",
    );
    expect(documentation).toContain("Raw stdout and stderr are retained as a private Engagement Log");
    expect(documentation).toContain(
      "Installing the reviewed executable alone grants no mission authority",
    );
  });
});
