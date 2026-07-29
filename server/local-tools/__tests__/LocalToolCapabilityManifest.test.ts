import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
  MAX_REVIEWED_TCP_PORT_SET_SIZE,
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
  type LocalToolActivationReceipt,
} from "../index";

const TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const NOW = new Date("2026-07-19T12:00:00.000Z");

function document(): Record<string, any> {
  return JSON.parse(readFileSync(TEMPLATE, "utf8")) as Record<string, any>;
}

function activation(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
  overrides: Partial<LocalToolActivationReceipt> = {},
): LocalToolActivationReceipt {
  const tool = manifest.resolve(toolId)!;
  return {
    schemaVersion: LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
    manifestSha256: manifest.descriptor.manifestSha256,
    toolId,
    bindingSha256: tool.bindingSha256,
    preflightBindingSha256: "b".repeat(64),
    executableSha256: tool.executable.expectedSha256,
    installationReady: true,
    isolatedProbeReady: true,
    invocationAdapterReady: true,
    workspaceConfinementReady: true,
    resultSinkReady: true,
    cancellationReady: true,
    observedAt: "2026-07-19T11:59:00.000Z",
    expiresAt: "2026-07-19T12:05:00.000Z",
    ...overrides,
  };
}

describe("LocalToolCapabilityManifest", () => {
  test("parses the reviewed Kali baseline and preserves deterministic routing", () => {
    const manifest = new LocalToolCapabilityManifest(document());
    expect(manifest.descriptor).toMatchObject({
      manifestVersion: "kali-local-baseline-2026.07.20",
      toolCount: 5,
      enabledToolCount: 4,
      sourceOfTruth: "reviewed-local-tool-capability-manifest",
    });
    expect(manifest.resolveRoute("http_metadata", "url")?.toolId)
      .toBe("kali:curl-http-metadata");
    expect(manifest.resolveRoute("dns_query", "domain")?.toolId)
      .toBe("kali:host-dns-query");
    expect(manifest.resolveRoute("host_liveness", "ip_or_host")?.toolId)
      .toBe("kali:ping-host-liveness");
    expect(manifest.resolveRoute("tcp_connect", "ip_or_host")?.toolId)
      .toBe("kali:ncat-tcp-connect");
    expect(manifest.resolveRoute("port_scan", "ip_or_host")).toBeUndefined();
    expect(manifest.resolve("kali:nmap-tcp-connect-service-scan")).toMatchObject({
      activation: "disabled",
      executable: {
        expectedSha256: "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f",
        fileCapabilities: "none",
      },
      actionClassIds: ["port_service_enumeration"],
    });
    expect(manifest.descriptor.manifestSha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  test("compiles the bounded nmap binding only after explicit activation", () => {
    const input = document();
    const nmap = input.tools.find(({ toolId }: { toolId: string }) =>
      toolId === "kali:nmap-tcp-connect-service-scan");
    nmap.activation = "enabled";
    nmap.activationReason = null;
    const manifest = new LocalToolCapabilityManifest(input);
    expect(manifest.resolveRoute("port_scan", "ip_or_host")?.toolId)
      .toBe("kali:nmap-tcp-connect-service-scan");
    const compiled = manifest.compileInvocation("kali:nmap-tcp-connect-service-scan", {
      workspace: "/engagements/reapertwo",
      target: "10.129.39.191",
      ports: "22,80,443",
    });
    expect(compiled).toMatchObject({
      shell: false,
      authorizationGranted: false,
      scopeEnforcementRequired: true,
      timeoutMs: 150_000,
      maximumOutputBytes: 2_097_152,
      terminationGraceMs: 2_000,
    });
    expect(compiled.arguments).toEqual([
      "-n", "-Pn", "-sT", "--open", "-p", "22,80,443",
      "-sV", "--version-light", "--max-retries", "1",
      "--max-rate", "500", "--max-parallelism", "64",
      "--host-timeout", "120s", "--max-rtt-timeout", "2s",
      "--", "10.129.39.191",
    ]);
    expect(compiled.arguments).not.toContain("-sS");
    expect(compiled.arguments).not.toContain("-O");
    expect(compiled.arguments).not.toContain("--script");
  });

  test("rejects nmap host sets, port ranges, option syntax, duplicates, and oversized scans", () => {
    const input = document();
    const nmap = input.tools.find(({ toolId }: { toolId: string }) =>
      toolId === "kali:nmap-tcp-connect-service-scan");
    nmap.activation = "enabled";
    nmap.activationReason = null;
    const manifest = new LocalToolCapabilityManifest(input);
    const compile = (target: string, ports: string) => manifest.compileInvocation(
      "kali:nmap-tcp-connect-service-scan",
      { workspace: "/engagements/review", target, ports },
    );
    expect(() => compile("10.0.0.0/24", "80")).toThrow("without a range, CIDR");
    expect(() => compile("10.0.0.1-10", "80")).toThrow("without a range, CIDR");
    expect(() => compile("--script=vuln", "80")).toThrow("without a range, CIDR");
    expect(() => compile("10.0.0.1", "80-443")).toThrow("ranges and option syntax");
    expect(() => compile("10.0.0.1", "80;443")).toThrow("ranges and option syntax");
    expect(() => compile("10.0.0.1", "080")).toThrow("ranges and option syntax");
    expect(() => compile("10.0.0.1", "443,80")).toThrow("canonical ascending order");
    expect(() => compile("10.0.0.1", "80,80")).toThrow("canonical ascending order");
    const oversized = Array.from(
      { length: MAX_REVIEWED_TCP_PORT_SET_SIZE + 1 },
      (_, index) => index + 1,
    ).join(",");
    expect(() => compile("10.0.0.1", oversized)).toThrow(
      `at most ${MAX_REVIEWED_TCP_PORT_SET_SIZE} TCP ports`,
    );
  });

  test("compiles exact direct argv without granting scope authority", () => {
    const manifest = new LocalToolCapabilityManifest(document());
    const compiled = manifest.compileInvocation("kali:ncat-tcp-connect", {
      workspace: "/engagements/reapertwo",
      target: "10.129.39.191",
      port: 443,
    });
    expect(compiled).toMatchObject({
      executablePath: "/usr/bin/ncat",
      logicalWorkspace: "/engagements/reapertwo",
      shell: false,
      scopeEnforcementRequired: true,
      authorizationGranted: false,
      timeoutMs: 10_000,
      maximumOutputBytes: 262_144,
      terminationGraceMs: 1_000,
      environment: {
        HOME: "/nonexistent",
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
      },
    });
    expect(compiled.arguments).toEqual([
      "--verbose", "-z", "--wait", "3", "--", "10.129.39.191", "443",
    ]);
    expect(compiled.bindingSha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  test("rejects option injection, credentials in URLs, unknown keys, and workspace traversal", () => {
    const manifest = new LocalToolCapabilityManifest(document());
    expect(() => manifest.compileInvocation("kali:ncat-tcp-connect", {
      workspace: "/engagements/test",
      target: "--exec=/tmp/x",
      port: 443,
    })).toThrow("normalized target token");
    expect(() => manifest.compileInvocation("kali:curl-http-metadata", {
      workspace: "/engagements/test",
      url: "https://user:password@example.test/",
    })).toThrow("without embedded credentials");
    expect(() => manifest.compileInvocation("kali:ping-host-liveness", {
      workspace: "/engagements/test",
      target: "10.0.0.1",
      extra: "not-allowed",
    })).toThrow("arguments must contain exactly");
    expect(() => manifest.compileInvocation("kali:host-dns-query", {
      workspace: "/engagements/../outside",
      name: "example.test",
      recordType: "A",
    })).toThrow("normalized absolute logical workspace");
  });

  test("keeps runtime tools unavailable until every receipt boundary is fresh and bound", () => {
    const manifest = new LocalToolCapabilityManifest(document());
    const cold = manifest.toRuntimeSourceManifests([], NOW);
    expect(cold.tools.every(({ available }) => !available)).toBeTrue();
    expect(cold.agents).toEqual([expect.objectContaining({ available: false })]);

    const enabled = manifest.list().filter(({ activation: state }) => state === "enabled");
    const receipts = enabled.map(({ toolId }) => activation(manifest, toolId));
    const ready = manifest.toRuntimeSourceManifests(receipts, NOW);
    expect(ready.tools.filter(({ id }) => id !== "kali:nmap-tcp-connect-service-scan")
      .every(({ available }) => available)).toBeTrue();
    expect(ready.tools.find(({ id }) => id === "kali:nmap-tcp-connect-service-scan"))
      .toMatchObject({ available: false });
    expect(ready.agents).toEqual([expect.objectContaining({ available: true })]);
    const projection = ready.tools.find(({ id }) => id === "kali:ncat-tcp-connect");
    expect(projection?.dependencies?.every(({ ready }) => ready)).toBeTrue();

    const stale = receipts.map((receipt, index) => index === 0
      ? { ...receipt, expiresAt: "2026-07-19T11:59:59.000Z" }
      : receipt);
    expect(manifest.toRuntimeSourceManifests(stale, NOW).tools
      .find(({ id }) => id === receipts[0]!.toolId)?.available).toBeFalse();
    const drifted = receipts.map((receipt, index) => index === 1
      ? { ...receipt, bindingSha256: "0".repeat(64) }
      : receipt);
    expect(manifest.toRuntimeSourceManifests(drifted, NOW).tools
      .find(({ id }) => id === receipts[1]!.toolId)?.available).toBeFalse();
    const missingPreflightBinding = receipts.map((receipt, index) => index === 2
      ? { ...receipt, preflightBindingSha256: null }
      : receipt);
    expect(manifest.toRuntimeSourceManifests(missingPreflightBinding, NOW).tools
      .find(({ id }) => id === receipts[2]!.toolId)?.available).toBeFalse();
  });

  test("adapts only enabled tools into the startup binding registry", () => {
    const input = document();
    input.tools[0].activation = "disabled";
    input.tools[0].activationReason = "Held for a new package review.";
    const manifest = new LocalToolCapabilityManifest(input);
    const registry = manifest.toToolBindingRegistryDocument();
    expect(registry.schemaVersion).toBe("ti-scale.tool-binding-registry.v1");
    expect(registry.bindings).toHaveLength(3);
    expect(registry.bindings.some(({ toolId }) => toolId === "kali:curl-http-metadata"))
      .toBeFalse();
  });

  test("rejects shell execution, ambiguous routing, and workspace interpolation", () => {
    const shell = document();
    shell.tools[0].execution.shell = true;
    expect(() => new LocalToolCapabilityManifest(shell)).toThrow("reviewed local boundary");

    const route = document();
    route.tools[1].routing = { ...route.tools[0].routing };
    expect(() => new LocalToolCapabilityManifest(route)).toThrow("ambiguous enabled route");

    const workspace = document();
    workspace.tools[0].argvTemplate.push({ kind: "parameter", value: "workspace" });
    expect(() => new LocalToolCapabilityManifest(workspace)).toThrow("logical workspace only");
  });

  test("returns a plain canonical document for trusted-file hashing", () => {
    const parsed = parseLocalToolCapabilityManifestDocument(document());
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect(parsed.tools).toHaveLength(5);
    expect("bindingSha256" in (parsed.tools[0] as unknown as Record<string, unknown>)).toBeFalse();
  });
});
