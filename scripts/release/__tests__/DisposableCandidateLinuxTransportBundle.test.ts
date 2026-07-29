import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

describe("disposable candidate Linux deployment policy", () => {
  test("uses the existing Ti-Scale account and a Unix-only restricted broker", () => {
    const service = readFileSync(
      "deployment/systemd/ti-scale-candidate-linux-broker.service",
      "utf8",
    );
    expect(service).toContain("User=ti-scale\n");
    expect(service).toContain("Group=ti-scale\n");
    expect(service).toContain("RestrictAddressFamilies=AF_UNIX");
    expect(service).toContain("UMask=0007");
    expect(service).toContain("NoNewPrivileges=yes");
    expect(service).not.toContain("SupplementaryGroups=");
    expect(service).not.toMatch(/ExecStart=.*(?:sh|bash) /u);
  });

  test("stages application activation as a drop-in without replacing the base service", () => {
    const dropIn = readFileSync(
      "deployment/systemd/ti-scale.service.d/80-candidate-linux-transport.conf",
      "utf8",
    );
    expect(dropIn).toContain(
      "Wants=ti-scale-candidate-linux-broker.service",
    );
    expect(dropIn).toContain(
      "After=ti-scale-candidate-linux-broker.service",
    );
    expect(dropIn).toContain(
      "EnvironmentFile=/etc/ti-scale/candidate-linux-runtime.env",
    );
    const installer = readFileSync(
      "scripts/install-disposable-candidate-linux-transport.ts",
      "utf8",
    );
    expect(installer).not.toContain('systemctl("restart"');
    expect(installer).toContain('"installed_not_activated"');
  });
});
