import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuthenticatedNmapActivationVerifier,
  exactAutonomousSafeReconActionClasses,
  exactNmapCapabilityAvailable,
} from "../AuthenticatedNmapActivationVerifier";

const TOOL_ID = "kali:nmap-tcp-connect-service-scan";
const DEPENDENCIES = [
  "operator-activation",
  "executable-integrity",
  "isolated-target-free-readiness",
  "direct-argv-adapter",
  "workspace-confinement",
  "result-sink",
  "cancellation",
] as const;
const NOW = new Date("2026-07-20T12:00:00.000Z");
const OBSERVED_AT = "2026-07-20T11:59:50.000Z";
const EXPIRES_AT = "2026-07-20T12:04:50.000Z";
const TOKEN = "test-only-operator-token-with-32-bytes";
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function exactResult(kind: "tool" | "tool_dependency", id: string) {
  return {
    id: `self-test:${kind}:${id}`,
    component: { kind, id, label: id },
    testKind: kind === "tool" ? "local_executable_attestation" : "manifest_dependency",
    status: "pass",
    availability: "available",
    checkedAt: NOW.toISOString(),
    freshness: {
      state: "fresh",
      observedAt: OBSERVED_AT,
      expiresAt: EXPIRES_AT,
      maximumAgeMs: null,
    },
    explanation: "Bounded local activation proof.",
    remediation: null,
    executionAuthorization: {
      state: "not_granted",
      grantsMissionExecution: false,
      explanation: "No mission authority is granted.",
    },
  };
}

function exactCapabilitySnapshot() {
  return {
    schemaVersion: "2.4",
    checkedAt: NOW.toISOString(),
    readOnly: true,
    grantsMissionExecution: false,
    accounting: {
      runtimeRegistryRead: true,
      manifestValid: true,
      complete: true,
      registered: { providers: 0, mcpServers: 0, tools: 1, toolDependencies: 7 },
      reported: { providers: 0, mcpServers: 0, tools: 1, toolDependencies: 7 },
    },
    summary: {
      total: 8,
      pass: 8,
      degraded: 0,
      fail: 0,
      available: 8,
      degradedAvailability: 0,
      unavailable: 0,
      unsupported: 0,
    },
    results: [
      exactResult("tool", TOOL_ID),
      ...DEPENDENCIES.map((dependency) =>
        exactResult("tool_dependency", `${TOOL_ID}/${dependency}`)),
    ],
  };
}

function healthyApplication() {
  return {
    schemaVersion: "2.4",
    status: "degraded",
    database: { healthy: true },
    eventStream: { status: "healthy", subscribers: 0 },
    execution: { autonomous: "ready", guided: "ready" },
    dependencies: {
      autonomousRuntime: {
        status: "ready",
        readyActionClassIds: [
          "active_host_discovery",
          "cve_intelligence_applicability_validation",
          "dns_domain_certificate_discovery",
          "exploit_validation",
          "os_technology_fingerprinting",
          "port_service_enumeration",
          "vulnerability_configuration_assessment",
          "web_content_endpoint_discovery_fuzzing",
          "web_crawling_page_capture",
        ],
        components: {
          localProcessExecution: true,
          mcpExecution: false,
          enforcingProvider: true,
          resultAwareSpecialistExecution: true,
        },
      },
      mcp: { status: "unavailable", runnableServers: 0 },
    },
  };
}

function healthyLiveness() {
  return {
    schemaVersion: "2.4",
    status: "healthy",
    service: "ti-scale",
    database: { healthy: true },
    eventStream: { status: "healthy", subscribers: 0 },
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function tokenFixture(): { readonly root: string; readonly path: string } {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-activation-token-"));
  temporaryDirectories.push(root);
  chmodSync(root, 0o700);
  const path = join(root, "operator-token");
  writeFileSync(path, TOKEN, { mode: 0o600 });
  chmodSync(path, 0o600);
  return { root, path };
}

describe("authenticated Nmap activation verification", () => {
  test("requires the exact canonical forward-only Safe Recon action-class sequence", () => {
    expect(exactAutonomousSafeReconActionClasses([
      "active_host_discovery",
      "cve_intelligence_applicability_validation",
      "dns_domain_certificate_discovery",
      "exploit_validation",
      "os_technology_fingerprinting",
      "port_service_enumeration",
      "vulnerability_configuration_assessment",
      "web_content_endpoint_discovery_fuzzing",
      "web_crawling_page_capture",
    ])).toBeTrue();

    const rejected = [
      [
        "active_host_discovery",
        "cve_intelligence_applicability_validation",
        "dns_domain_certificate_discovery",
        "exploit_validation",
        "os_technology_fingerprinting",
        "port_service_enumeration",
        "vulnerability_configuration_assessment",
        "web_content_endpoint_discovery_fuzzing",
      ],
      [
        "active_host_discovery",
        "cve_intelligence_applicability_validation",
        "dns_domain_certificate_discovery",
        "exploit_validation",
        "os_technology_fingerprinting",
        "port_service_enumeration",
        "vulnerability_configuration_assessment",
        "web_content_endpoint_discovery_fuzzing",
        "web_crawling_page_capture",
        "destructive_data_system_modification",
      ],
      [
        "active_host_discovery",
        "cve_intelligence_applicability_validation",
        "dns_domain_certificate_discovery",
        "dns_domain_certificate_discovery",
        "exploit_validation",
        "os_technology_fingerprinting",
        "port_service_enumeration",
        "vulnerability_configuration_assessment",
        "web_content_endpoint_discovery_fuzzing",
        "web_crawling_page_capture",
      ],
      [
        "cve_intelligence_applicability_validation",
        "dns_domain_certificate_discovery",
        "active_host_discovery",
        "exploit_validation",
        "os_technology_fingerprinting",
        "port_service_enumeration",
        "vulnerability_configuration_assessment",
        "web_content_endpoint_discovery_fuzzing",
        "web_crawling_page_capture",
      ],
      [
        "active_host_discovery",
        "cve_intelligence_applicability_validation",
        "dns_domain_certificate_discovery",
        "exploit_validation",
        "os_technology_fingerprinting",
        "port_and_service_enumeration",
        "vulnerability_configuration_assessment",
        "web_content_endpoint_discovery_fuzzing",
        "web_crawling_page_capture",
      ],
    ];
    for (const actionClassIds of rejected) {
      expect(exactAutonomousSafeReconActionClasses(actionClassIds)).toBeFalse();
    }
  });

  test("accepts only one exact fresh Nmap tool joined to all seven activation dependencies", () => {
    const snapshot = exactCapabilitySnapshot();
    expect(exactNmapCapabilityAvailable(snapshot, NOW)).toBeTrue();

    const missing = structuredClone(snapshot);
    missing.results.pop();
    expect(exactNmapCapabilityAvailable(missing, NOW)).toBeFalse();

    const divergent = structuredClone(snapshot);
    divergent.results[2]!.freshness.observedAt = "2026-07-20T11:59:49.000Z";
    expect(exactNmapCapabilityAvailable(divergent, NOW)).toBeFalse();

    const granted = structuredClone(snapshot);
    granted.results[0]!.executionAuthorization.grantsMissionExecution = true as false;
    expect(exactNmapCapabilityAvailable(granted, NOW)).toBeFalse();
  });

  test("proves HTTP/database/event health and performs an authenticated read-only capability self-test", async () => {
    const token = tokenFixture();
    const requests: Array<{ readonly path: string; readonly authorization: string | null }> = [];
    const verifier = new AuthenticatedNmapActivationVerifier({
      baseUrl: "http://127.0.0.1:3132",
      tokenPath: token.path,
      tokenTrustRoot: token.root,
      clock: () => NOW,
      fetch: (async (input, init) => {
        const url = new URL(String(input));
        const headers = new Headers(init?.headers);
        requests.push({ path: url.pathname, authorization: headers.get("Authorization") });
        return url.pathname === "/api/v2/health"
          ? jsonResponse(healthyLiveness())
          : url.pathname === "/api/v2/system/readiness"
            ? jsonResponse(healthyApplication())
            : jsonResponse(exactCapabilitySnapshot());
      }),
    });

    await verifier.verifyActivated(TOOL_ID);
    expect(requests).toEqual([
      { path: "/api/v2/health", authorization: null },
      { path: "/api/v2/system/readiness", authorization: null },
      { path: "/api/v2/system/capability-self-tests", authorization: `Bearer ${TOKEN}` },
    ]);
  });

  test("rejects an active HTTP process whose database health is false", async () => {
    const token = tokenFixture();
    const verifier = new AuthenticatedNmapActivationVerifier({
      tokenPath: token.path,
      tokenTrustRoot: token.root,
      activationDeadlineMs: 4,
      pollIntervalMs: 1,
      fetch: (async (input) => new URL(String(input)).pathname === "/api/v2/health"
        ? jsonResponse({ ...healthyLiveness(), database: { healthy: false } })
        : jsonResponse(healthyApplication())),
    });
    await expect(verifier.verifyActivated(TOOL_ID)).rejects.toThrow(
      "did not prove HTTP health and exact fresh Nmap availability",
    );
  });

  test("accepts reviewed local-process Autonomous readiness without a global MCP route and rejects an MCP-shaped substitute", async () => {
    const token = tokenFixture();
    const requests: string[] = [];
    const verifier = new AuthenticatedNmapActivationVerifier({
      tokenPath: token.path,
      tokenTrustRoot: token.root,
      clock: () => NOW,
      fetch: (async (input) => {
        const path = new URL(String(input)).pathname;
        requests.push(path);
        return path === "/api/v2/health"
          ? jsonResponse(healthyLiveness())
          : path === "/api/v2/system/readiness"
            ? jsonResponse(healthyApplication())
            : jsonResponse(exactCapabilitySnapshot());
      }),
    });
    await verifier.verifyActivated(TOOL_ID);
    expect(requests).toEqual([
      "/api/v2/health",
      "/api/v2/system/readiness",
      "/api/v2/system/capability-self-tests",
    ]);

    const mcpShaped = structuredClone(healthyApplication());
    mcpShaped.dependencies.autonomousRuntime.components.localProcessExecution = false;
    mcpShaped.dependencies.autonomousRuntime.components.mcpExecution = true;
    const rejected = new AuthenticatedNmapActivationVerifier({
      tokenPath: token.path,
      tokenTrustRoot: token.root,
      activationDeadlineMs: 4,
      pollIntervalMs: 1,
      fetch: async (input) => new URL(String(input)).pathname === "/api/v2/health"
        ? jsonResponse(healthyLiveness())
        : jsonResponse(mcpShaped),
    });
    await expect(rejected.verifyActivated(TOOL_ID)).rejects.toThrow(
      "did not prove HTTP health and exact fresh Nmap availability",
    );
  });

  test("rejects fresh HTTP health when Nmap or one joined dependency is unavailable without leaking the token", async () => {
    const token = tokenFixture();
    const unavailable = exactCapabilitySnapshot();
    unavailable.results[3]!.status = "fail";
    unavailable.results[3]!.availability = "unavailable";
    const verifier = new AuthenticatedNmapActivationVerifier({
      tokenPath: token.path,
      tokenTrustRoot: token.root,
      activationDeadlineMs: 4,
      pollIntervalMs: 1,
      clock: () => NOW,
      fetch: (async (input) => {
        const path = new URL(String(input)).pathname;
        return path === "/api/v2/health"
          ? jsonResponse(healthyLiveness())
          : path === "/api/v2/system/readiness"
            ? jsonResponse(healthyApplication())
            : jsonResponse(unavailable);
      }),
    });
    let failure = "";
    try {
      await verifier.verifyActivated(TOOL_ID);
    } catch (error) {
      failure = error instanceof Error ? error.message : String(error);
    }
    expect(failure).toContain("did not prove HTTP health and exact fresh Nmap availability");
    expect(failure).not.toContain(TOKEN);
  });

  test("prior-state verification requires a live database and event stream but no operator token read", async () => {
    const verifier = new AuthenticatedNmapActivationVerifier({
      tokenPath: "/path/that/must/not/be/read",
      fetch: async () => jsonResponse(healthyLiveness()),
    });
    await verifier.verifyPriorServiceHealthy();
  });
});
