import { describe, expect, test } from "bun:test";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const unitPath = join(root, "deployment/systemd/ti-scale-mcp-nvd.service");
const hostDropInPath = join(root, "deployment/systemd/ti-scale.service.d/20-public-nvd-mcp.conf");
const sysusersPath = join(root, "deployment/sysusers.d/ti-scale-mcp-nvd.conf");
const credentialHelperPath = join(root, "scripts/install-public-nvd-mcp-credential.sh");
const smokeHelperPath = join(root, "scripts/smoke-public-nvd-mcp.ts");
const documentationPath = join(root, "docs/public-nvd-mcp.md");
const sidecarPath = join(root, "server/mcp-public-nvd/PublicNvdHttpSidecar.ts");

describe("public NVD production deployment artifacts", () => {
  test("runs under a dedicated identity with a credential mount and fixed loopback port", () => {
    const unit = readFileSync(unitPath, "utf8");
    expect(unit).toContain("User=ti-scale-mcp-nvd");
    expect(unit).toContain("Group=ti-scale-mcp-nvd");
    expect(unit).toContain("LoadCredential=mcp-token:/etc/ti-scale-mcp-nvd/mcp-token");
    expect(unit).toContain("Environment=TI_SCALE_PUBLIC_NVD_MCP_PORT=43142");
    expect(unit).toContain("Environment=TI_SCALE_PUBLIC_NVD_MCP_TOKEN_FILE=%d/mcp-token");
    expect(unit).toContain("SocketBindAllow=ipv4:tcp:43142");
    expect(unit).toContain("SocketBindDeny=any");
    expect(unit).not.toMatch(/^Environment=.*(?:HOST|BIND)=/m);
    expect(unit).not.toMatch(/^ListenStream=/m);

    const sidecar = readFileSync(sidecarPath, "utf8");
    expect(sidecar).toContain(
      '"/run/credentials/ti-scale-mcp-nvd.service/mcp-token"',
    );

    const hostDropIn = readFileSync(hostDropInPath, "utf8");
    expect(hostDropIn).toContain(
      "LoadCredential=public-nvd-mcp-token:/etc/ti-scale-mcp-nvd/mcp-token",
    );
    expect(hostDropIn).not.toMatch(/^Environment=.*(?:TOKEN|SECRET|AUTHORIZATION)=/m);

    const sysusers = readFileSync(sysusersPath, "utf8");
    expect(sysusers).toMatch(/^u\s+ti-scale-mcp-nvd\s+-/m);
    expect(sysusers).toContain("/nonexistent");
    expect(sysusers).toContain("/usr/sbin/nologin");
  });

  test("denies persistent product data and bounds service privileges and resources", () => {
    const unit = readFileSync(unitPath, "utf8");
    expect(unit).toContain("ProtectSystem=strict");
    expect(unit).toContain("ProtectHome=yes");
    expect(unit).toContain("InaccessiblePaths=-/etc/ti-scale -/etc/ti-scale-mcp-nvd -/var/lib/ti-scale -/var/backups/ti-scale");
    expect(unit).toContain("CapabilityBoundingSet=\n");
    expect(unit).toContain("NoNewPrivileges=yes");
    expect(unit).toContain("SystemCallFilter=@system-service");
    expect(unit).toContain("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6");
    expect(unit).toContain("MemoryMax=256M");
    expect(unit).toContain("TasksMax=64");
    expect(unit).not.toMatch(/^ReadWritePaths=/m);
    expect(unit).not.toMatch(/^StateDirectory=/m);
  });

  test("keeps credential installation and smoke checking secret-safe", () => {
    const installer = readFileSync(credentialHelperPath, "utf8");
    expect(installer).toContain("openssl rand -hex 32 >\"$temporary\"");
    expect(installer).toContain("refusing to place a bearer credential inside a Git working tree");
    expect(installer).not.toMatch(/set\s+-x/u);
    expect(installer).not.toMatch(/git\s+(?:add|commit)/u);
    expect(statSync(credentialHelperPath).mode & 0o111).not.toBe(0);

    const smoke = readFileSync(smokeHelperPath, "utf8");
    expect(smoke).toContain("PUBLIC_NVD_MCP_DEFAULT_PORT");
    expect(smoke).toContain("PUBLIC_NVD_INPUT_SCHEMA_SHA256");
    expect(smoke).toContain("PUBLIC_NVD_OUTPUT_SCHEMA_SHA256");
    expect(smoke).toContain("credential.fill(0)");
    expect(smoke).not.toContain("console.log");
    expect(statSync(smokeHelperPath).mode & 0o111).not.toBe(0);
  });

  test("documents standalone operation, rotation, graceful stop, and forward replacement", () => {
    const documentation = readFileSync(documentationPath, "utf8");
    for (const heading of [
      "## Architecture",
      "## Trust boundary",
      "## Health and smoke checks",
      "## Credential rotation",
      "## Graceful shutdown",
      "## Forward replacement",
    ]) {
      expect(documentation).toContain(heading);
    }
  });
});
