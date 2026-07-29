import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverLegacyEngagements } from "../LegacyEngagementDiscovery";
import { parseLegacyReconSemantics } from "../LegacyReconSemanticParser";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});
function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-recon-semantics-"));
  temporaryDirectories.push(directory);
  return directory;
}

describe("LegacyReconSemanticParser", () => {
  test("extracts bounded Nmap and grepable host/service observations with historical provenance", async () => {
    const root = temporaryDirectory();
    const scans = join(root, "reapertwo", "scans");
    mkdirSync(scans, { recursive: true });
    writeFileSync(join(scans, "services.nmap"), [
      "Nmap scan report for Reaper2 (10.129.234.76)",
      "Host is up (0.0040s latency).",
      "PORT     STATE SERVICE       VERSION",
      "80/tcp   open  http          Microsoft IIS httpd 10.0",
      "3389/tcp open  ms-wbt-server Microsoft Terminal Services",
      "Running: Microsoft Windows 2022",
      "",
    ].join("\n"));
    writeFileSync(
      join(scans, "fast.gnmap"),
      "Host: 10.129.234.77 (web-02) Status: Up\tPorts: 443/open/tcp//https//nginx 1.24/, 53/closed/udp//domain///\tOS: Linux 6.X\n",
    );

    const discovery = await discoverLegacyEngagements([root]);
    expect(discovery.manifests).toHaveLength(1);
    const parsed = parseLegacyReconSemantics(discovery.manifests[0]!);

    expect(parsed.issues).toEqual([]);
    expect(parsed.hosts).toHaveLength(2);
    expect(parsed.hosts[0]).toMatchObject({
      address: "10.129.234.76",
      hostname: "Reaper2",
      hostStatus: "up",
      osHints: ["Microsoft Windows 2022"],
    });
    expect(parsed.hosts[0]!.services).toEqual([
      { port: 80, transport: "tcp", state: "open", serviceName: "http", productVersion: "Microsoft IIS httpd 10.0" },
      { port: 3389, transport: "tcp", state: "open", serviceName: "ms-wbt-server", productVersion: "Microsoft Terminal Services" },
    ]);
    expect(parsed.hosts[1]).toMatchObject({
      address: "10.129.234.77",
      hostname: "web-02",
      hostStatus: "up",
      osHints: ["Linux 6.X"],
      services: [{ port: 443, transport: "tcp", state: "open", serviceName: "https", productVersion: "nginx 1.24" }],
    });
  });

  test("refuses semantic projection when a source changes after hash discovery", async () => {
    const root = temporaryDirectory();
    const scan = join(root, "authorized-lab", "scans", "services.nmap");
    mkdirSync(join(scan, ".."), { recursive: true });
    writeFileSync(scan, "Nmap scan report for 192.0.2.10\nHost is up.\n80/tcp open http nginx\n");

    const discovery = await discoverLegacyEngagements([root]);
    const manifest = discovery.manifests[0]!;
    writeFileSync(scan, "Nmap scan report for 192.0.2.99\nHost is up.\n22/tcp open ssh OpenSSH\n");

    const parsed = parseLegacyReconSemantics(manifest);
    expect(parsed.hosts).toEqual([]);
    expect(parsed.issues).toEqual([{
      relativePath: "scans/services.nmap",
      code: "source_changed",
      explanation: "Recon artifact changed after discovery and was not semantically projected.",
    }]);
  });
});
