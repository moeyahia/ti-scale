import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const policy = new URL(
  "../../../deployment/systemd/ti-scale.service.d/40-reviewed-local-tools.conf",
  import.meta.url,
);

describe("reviewed local tool systemd policy", () => {
  test("permits only the socket families required by the host and isolated probe", () => {
    const document = readFileSync(policy, "utf8");
    expect(document).toContain("RestrictAddressFamilies=\n");
    expect(document).toContain(
      "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
    );
    expect(document).not.toMatch(/AF_PACKET|AF_BLUETOOTH|AF_VSOCK|AF_XDP/u);
  });
});
