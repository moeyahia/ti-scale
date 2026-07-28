import { describe, expect, test } from "bun:test";
import type { ActionClassId } from "../../domain";
import {
  projectInstalledKaliToolInventory,
  type InstalledKaliAliasDefinition,
  type InstalledKaliExecutableInspection,
  type InstalledKaliReviewedRoute,
} from "../InstalledKaliToolInventory";

const PORT_SCAN = "port_service_enumeration" satisfies ActionClassId;
const DNS = "dns_domain_certificate_discovery" satisfies ActionClassId;

function alias(
  name: string,
  declaredTool: string,
  actionClassId: ActionClassId = PORT_SCAN,
): InstalledKaliAliasDefinition {
  return { section: "Fixture tools", alias: name, declaredTool, actionClassId };
}

function inspection(input: Partial<InstalledKaliExecutableInspection> & Readonly<{
  resolvedPath: string;
  sha256: string;
}>): InstalledKaliExecutableInspection {
  return {
    uid: 0,
    mode: 0o755,
    serviceUserExecutable: true,
    fileCapabilities: "none",
    ...input,
  };
}

function route(input: Partial<InstalledKaliReviewedRoute> & Readonly<{
  toolId: string;
  executablePath: string;
  expectedSha256: string;
}>): InstalledKaliReviewedRoute {
  return {
    actionClassIds: [PORT_SCAN],
    runtimeAvailability: "available",
    ...input,
  };
}

describe("installed Kali tool inventory projection", () => {
  test("keeps installation truth separate from runtime activation truth", () => {
    const aliases = [
      alias("RESOLVE", "host", DNS),
      alias("SURFACE", "nmap"),
      alias("PEEK", "rustscan"),
      alias("CUSTOM", "custom-tool"),
    ];
    const inspections = new Map<string, InstalledKaliExecutableInspection | null>([
      ["RESOLVE", inspection({ resolvedPath: "/usr/bin/host", sha256: "a".repeat(64) })],
      ["SURFACE", inspection({
        resolvedPath: "/usr/bin/nmap",
        sha256: "b".repeat(64),
        fileCapabilities: "/usr/bin/nmap cap_net_raw=eip",
      })],
      ["PEEK", null],
      ["CUSTOM", inspection({ resolvedPath: "/usr/bin/custom-tool", sha256: "c".repeat(64) })],
    ]);
    const reviewedRoutes = [
      route({
        toolId: "kali:host-dns-query",
        executablePath: "/usr/bin/host",
        expectedSha256: "a".repeat(64),
        actionClassIds: [DNS],
      }),
      route({
        toolId: "kali:nmap-tcp-connect-service-scan",
        executablePath: "/opt/ti-scale-toolchain/nmap/hash/nmap",
        expectedSha256: "d".repeat(64),
      }),
      route({
        toolId: "kali:ping-host-liveness",
        executablePath: "/usr/bin/ping",
        expectedSha256: "e".repeat(64),
        actionClassIds: ["active_host_discovery"],
      }),
    ];

    const snapshot = projectInstalledKaliToolInventory({ aliases, inspections, reviewedRoutes });
    expect(snapshot).toMatchObject({
      schemaVersion: "ti-scale.installed-kali-tool-inventory.v2",
      readOnly: true,
      targetInteraction: false,
      grantsMissionExecution: false,
      accounting: {
        aliases: 4,
        installedRunnable: 2,
        missing: 1,
        serviceUserUnavailable: 0,
        privilegeConflicts: 1,
        trustConflicts: 0,
        inspectionIncomplete: 0,
        runtimeReadyExactBindings: 1,
        runtimeReadyReviewedAlternatives: 1,
        reviewedBindingsNotReady: 0,
        reviewedAlternativesNotReady: 0,
        adapterReviewRequired: 1,
        installationBlocked: 1,
        reviewedRoutes: 3,
        runtimeReadyRoutes: 3,
        runtimeRoutesWithoutAliasMatch: 1,
      },
      runtimeRoutesWithoutAliasMatch: ["kali:ping-host-liveness"],
    });

    expect(snapshot.tools.find(({ alias: id }) => id === "RESOLVE")).toMatchObject({
      installationState: "installed_runnable",
      activationState: "runtime_ready_exact_binding",
      directAliasExecutionReady: true,
      missionCapabilityReady: true,
      reviewedToolId: "kali:host-dns-query",
      reviewedRouteKind: "exact_binding",
      blockers: [],
    });
    expect(snapshot.tools.find(({ alias: id }) => id === "SURFACE")).toMatchObject({
      installationState: "no_new_privileges_conflict",
      activationState: "runtime_ready_reviewed_alternative",
      directAliasExecutionReady: false,
      missionCapabilityReady: true,
      reviewedToolId: "kali:nmap-tcp-connect-service-scan",
      reviewedRouteKind: "reviewed_alternative",
      blockers: ["no_new_privileges_file_capability_conflict"],
    });
    expect(snapshot.tools.find(({ alias: id }) => id === "PEEK")).toMatchObject({
      installationState: "missing",
      activationState: "installation_blocked",
      missionCapabilityReady: false,
      blockers: [
        "executable_missing",
        "not_in_canonical_runtime_registry",
        "missing_pinned_argument_schema",
        "missing_target_free_probe_receipt",
        "missing_workspace_result_and_cancellation_receipts",
      ],
    });
    expect(snapshot.tools.find(({ alias: id }) => id === "CUSTOM")).toMatchObject({
      installationState: "installed_runnable",
      activationState: "adapter_review_required",
      directAliasExecutionReady: false,
      missionCapabilityReady: false,
    });
  });

  test("never labels a configured route ready without a fresh runtime projection", () => {
    const snapshot = projectInstalledKaliToolInventory({
      aliases: [alias("RESOLVE", "host", DNS)],
      inspections: new Map([["RESOLVE", inspection({
        resolvedPath: "/usr/bin/host",
        sha256: "a".repeat(64),
      })]]),
      reviewedRoutes: [route({
        toolId: "kali:host-dns-query",
        executablePath: "/usr/bin/host",
        expectedSha256: "a".repeat(64),
        actionClassIds: [DNS],
        runtimeAvailability: "unknown",
      })],
    });

    expect(snapshot.accounting.runtimeReadyExactBindings).toBe(0);
    expect(snapshot.accounting.reviewedBindingsNotReady).toBe(1);
    expect(snapshot.tools[0]).toMatchObject({
      activationState: "reviewed_binding_not_ready",
      directAliasExecutionReady: false,
      missionCapabilityReady: false,
      blockers: ["reviewed_runtime_receipt_unavailable"],
    });
  });

  test("does not treat a same-name executable as an alternative across action classes", () => {
    const snapshot = projectInstalledKaliToolInventory({
      aliases: [alias("SURFACE", "nmap")],
      inspections: new Map([["SURFACE", inspection({
        resolvedPath: "/usr/bin/nmap",
        sha256: "b".repeat(64),
      })]]),
      reviewedRoutes: [route({
        toolId: "kali:nmap-different-policy",
        executablePath: "/opt/reviewed/nmap",
        expectedSha256: "d".repeat(64),
        actionClassIds: [DNS],
      })],
    });

    expect(snapshot.tools[0]?.activationState).toBe("adapter_review_required");
    expect(snapshot.tools[0]?.reviewedToolId).toBeNull();
    expect(snapshot.runtimeRoutesWithoutAliasMatch).toEqual(["kali:nmap-different-policy"]);
  });

  test("rejects duplicate aliases, duplicate routes, and unexpected inspection records", () => {
    const routeRecord = route({
      toolId: "kali:host-dns-query",
      executablePath: "/usr/bin/host",
      expectedSha256: "a".repeat(64),
      actionClassIds: [DNS],
    });
    expect(() => projectInstalledKaliToolInventory({
      aliases: [alias("RESOLVE", "host", DNS), alias("RESOLVE", "host", DNS)],
      inspections: new Map(),
      reviewedRoutes: [],
    })).toThrow("duplicate alias RESOLVE");
    expect(() => projectInstalledKaliToolInventory({
      aliases: [alias("RESOLVE", "host", DNS)],
      inspections: new Map(),
      reviewedRoutes: [routeRecord, routeRecord],
    })).toThrow("duplicate reviewed route kali:host-dns-query");
    expect(() => projectInstalledKaliToolInventory({
      aliases: [alias("RESOLVE", "host", DNS)],
      inspections: new Map([["UNKNOWN", null]]),
      reviewedRoutes: [],
    })).toThrow("unexpected alias UNKNOWN");
  });
});
