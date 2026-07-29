#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { resolve } from "node:path";
import {
  ACTION_CLASS_DEFINITIONS,
  type ActionClassId,
} from "../server/domain";
import {
  loadTrustedLocalToolCapabilityManifest,
} from "../server/local-tools";
import {
  projectInstalledKaliToolInventory,
  type InstalledKaliExecutableInspection,
} from "../server/system-capabilities";
import { parseCapabilitySelfTestSnapshot } from "../src/domain/schemas/capabilitySelfTests";

const ALIAS_INVENTORY = "/opt/chillspwn-bin/ALIASES.md";
const ALIAS_ROOT = "/opt/chillspwn-bin";
const SERVICE_USER = "ti-scale";
const GETCAP = "/usr/sbin/getcap";
const RUNUSER = "/usr/sbin/runuser";
const READELF = "/usr/bin/readelf";
const SOURCE_ROOT = resolve(import.meta.dir, "..");
const MANIFEST_PATH = resolve(
  SOURCE_ROOT,
  "deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
);
const MANIFEST_SHA256 =
  "8a0ac74f4ef2f1988e4725e866d02c262b1875c1eee401f3cca0ce9e10766616";
const MAX_ALIAS_INVENTORY_BYTES = 256 * 1_024;
const MAX_TOOL_BYTES = 256 * 1_024 * 1_024;
const MAX_INSPECTION_OUTPUT_BYTES = 1 * 1_024 * 1_024;
const MAX_RUNTIME_READINESS_BYTES = 2 * 1_024 * 1_024;

const REQUIRED_ACTIVATION_DEPENDENCIES = Object.freeze([
  "operator-activation",
  "executable-integrity",
  "isolated-target-free-readiness",
  "direct-argv-adapter",
  "workspace-confinement",
  "result-sink",
  "cancellation",
] as const);

const POLICY_CLASS_BY_ALIAS: Readonly<Record<string, ActionClassId>> = Object.freeze({
  SURFACE: "port_service_enumeration",
  WIDE: "port_service_enumeration",
  PEEK: "port_service_enumeration",
  QUICK: "port_service_enumeration",
  LIVE: "web_crawling_page_capture",
  NET: "active_host_discovery",
  NAME: "active_host_discovery",
  BROWSE: "web_content_endpoint_discovery_fuzzing",
  WALK: "web_content_endpoint_discovery_fuzzing",
  SEEK: "web_content_endpoint_discovery_fuzzing",
  PAGE: "web_content_endpoint_discovery_fuzzing",
  TRY: "web_content_endpoint_discovery_fuzzing",
  SHOW: "os_technology_fingerprinting",
  READ: "vulnerability_configuration_assessment",
  AUDIT: "vulnerability_configuration_assessment",
  FACE: "vulnerability_configuration_assessment",
  MARK: "exploit_validation",
  MIX: "exploit_validation",
  QUERY: "exploit_validation",
  LOOKUP: "dns_domain_certificate_discovery",
  RESOLVE: "dns_domain_certificate_discovery",
  FWD: "dns_domain_certificate_discovery",
  BATCH: "dns_domain_certificate_discovery",
  LOT: "dns_domain_certificate_discovery",
  COLLECT: "dns_domain_certificate_discovery",
  HARVEST: "passive_intelligence_osint",
  GATHER: "passive_intelligence_osint",
  SHARE: "active_directory_identity_operations",
  SHARE2: "lateral_movement_pivoting",
  MAP: "active_directory_identity_operations",
  GRAB: "data_access_impact_validation",
  DOOR: "active_directory_identity_operations",
  LIST: "active_directory_identity_operations",
  DCOM: "active_directory_identity_operations",
  STORE: "active_directory_identity_operations",
  EDIT: "active_directory_identity_operations",
  LDAP: "active_directory_identity_operations",
  AD: "active_directory_identity_operations",
  VIEW2: "active_directory_identity_operations",
  GRAPH: "active_directory_identity_operations",
  TRACE: "active_directory_identity_operations",
  ROAST: "credential_password_hash_assessment",
  ASREP: "credential_password_hash_assessment",
  KERBEROS: "authentication_testing",
  SILVER: "authentication_testing",
  TICKET: "authentication_testing",
  PAC: "active_directory_identity_operations",
  SID: "active_directory_identity_operations",
  DELEGATE: "active_directory_identity_operations",
  RBCD: "privilege_escalation",
  DACL: "privilege_escalation",
  OWNER: "privilege_escalation",
  JOIN: "active_directory_identity_operations",
  CHILD: "privilege_escalation",
  PASSWORD: "authentication_testing",
  GETUSER: "active_directory_identity_operations",
  DUMP: "active_directory_identity_operations",
  REGISTRY: "active_directory_identity_operations",
  SERVICE: "active_directory_identity_operations",
  ENTER: "command_session_execution",
  STEP: "lateral_movement_pivoting",
  TASK: "lateral_movement_pivoting",
  PIPE: "lateral_movement_pivoting",
  SEND: "lateral_movement_pivoting",
  NOTE: "lateral_movement_pivoting",
  KEEP: "data_access_impact_validation",
  DPAPI: "data_access_impact_validation",
  MATCH: "credential_password_hash_assessment",
  GUESS: "credential_password_hash_assessment",
  GPU: "credential_password_hash_assessment",
  KUSER: "authentication_testing",
  RETRY: "authentication_testing",
  REPEAT: "authentication_testing",
  ROUND: "authentication_testing",
  PUSH: "authentication_testing",
  LABEL: "credential_password_hash_assessment",
  NAME2: "credential_password_hash_assessment",
  GENERATE: "credential_password_hash_assessment",
  TUN: "lateral_movement_pivoting",
  LINK: "lateral_movement_pivoting",
  CHAIN: "lateral_movement_pivoting",
  HOOK: "lateral_movement_pivoting",
  LISTEN: "lateral_movement_pivoting",
  RELAY: "lateral_movement_pivoting",
  TRAP: "data_access_impact_validation",
  WIRES: "data_access_impact_validation",
  LOCK: "vulnerability_configuration_assessment",
  TLS: "vulnerability_configuration_assessment",
  CRAFT: "exploit_validation",
  DESK: "exploit_validation",
  FIND: "cve_intelligence_applicability_validation",
  META: "reverse_engineering_binary_analysis",
  CARVE: "reverse_engineering_binary_analysis",
  RECOVER: "reverse_engineering_binary_analysis",
  PKI: "active_directory_identity_operations",
  DB: "data_access_impact_validation",
  GOTO: "active_directory_identity_operations",
});

interface AliasRecord {
  readonly section: string;
  readonly alias: string;
  readonly declaredTool: string;
}

interface InspectedPath {
  readonly resolvedPath: string;
  readonly sha256: string;
  readonly uid: number;
  readonly gid: number;
  readonly mode: number;
  readonly serviceUserExecutable: boolean;
  readonly fileCapabilities: string | null;
  readonly interpreter: string | null;
  readonly elfNeededLibraries: readonly string[];
}

function boundedRead(path: string, maximum: number): Buffer {
  const before = lstatSync(path, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile() || before.size < 1n
    || before.size > BigInt(maximum)) {
    throw new Error(`Refusing unsafe or oversized audit source ${path}`);
  }
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size
      || before.mtimeNs !== opened.mtimeNs || before.ctimeNs !== opened.ctimeNs) {
      throw new Error(`Audit source changed before read: ${path}`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs || opened.ctimeNs !== after.ctimeNs) {
      throw new Error(`Audit source changed during read: ${path}`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function aliases(): readonly AliasRecord[] {
  const text = boundedRead(ALIAS_INVENTORY, MAX_ALIAS_INVENTORY_BYTES).toString("utf8");
  const records: AliasRecord[] = [];
  let section = "Uncategorized";
  for (const line of text.split(/\r?\n/u)) {
    const heading = /^##\s+(.+)$/u.exec(line);
    if (heading) section = heading[1]!.trim();
    const match = /^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|$/u.exec(line);
    if (!match) continue;
    records.push(Object.freeze({
      section,
      alias: match[1]!,
      declaredTool: match[2]!,
    }));
  }
  if (records.length < 1 || records.length > 256
    || new Set(records.map(({ alias }) => alias)).size !== records.length) {
    throw new Error("The Kali alias inventory is empty, duplicated, or unexpectedly large");
  }
  const unmapped = records.filter(({ alias }) => !POLICY_CLASS_BY_ALIAS[alias]);
  if (unmapped.length > 0 || Object.keys(POLICY_CLASS_BY_ALIAS).length !== records.length) {
    throw new Error(`Policy mapping does not exactly cover the alias inventory: ${unmapped.map(({ alias }) => alias).join(",")}`);
  }
  return Object.freeze(records);
}

interface InspectionCommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function command(path: string, args: readonly string[]): InspectionCommandResult {
  const result = spawnSync(path, [...args], {
    encoding: "utf8",
    env: { HOME: "/nonexistent", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
    maxBuffer: MAX_INSPECTION_OUTPUT_BYTES,
    shell: false,
    timeout: 2_000,
    windowsHide: true,
  });
  return Object.freeze({
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  });
}

function inspect(alias: string): InspectedPath | null {
  const aliasPath = resolve(ALIAS_ROOT, alias);
  if (aliasPath !== `${ALIAS_ROOT}/${alias}`) throw new Error(`Unsafe alias ${alias}`);
  let resolvedPath: string;
  try { resolvedPath = realpathSync(aliasPath); }
  catch { return null; }
  const bytes = boundedRead(resolvedPath, MAX_TOOL_BYTES);
  const stat = lstatSync(resolvedPath);
  const capability = command(GETCAP, ["-n", "--", resolvedPath]);
  const capabilityText = capability.status === 0 ? capability.stdout.trim() : null;
  const executable = command(RUNUSER, ["-u", SERVICE_USER, "--", "test", "-x", aliasPath]);
  const firstLine = bytes.subarray(0, Math.min(bytes.length, 512)).toString("utf8").split(/\r?\n/u)[0] ?? "";
  const interpreter = firstLine.startsWith("#!") ? firstLine.slice(2).trim() : null;
  let needed: readonly string[] = [];
  if (!interpreter) {
    const dynamic = command(READELF, ["-d", resolvedPath]);
    if (dynamic.status === 0) {
      needed = Object.freeze([...dynamic.stdout.matchAll(/\(NEEDED\).*\[([^\]]+)\]/gu)]
        .map((match) => match[1]!)
        .sort((left, right) => left.localeCompare(right)));
    }
  }
  bytes.fill(0);
  return Object.freeze({
    resolvedPath,
    sha256: createHash("sha256").update(boundedRead(resolvedPath, MAX_TOOL_BYTES)).digest("hex"),
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode & 0o7777,
    serviceUserExecutable: executable.status === 0,
    fileCapabilities: capabilityText || (capability.status === 0 ? "none" : null),
    interpreter,
    elfNeededLibraries: needed,
  });
}

function runtimeAvailabilityByTool(now: Date): Readonly<{
  source: "not_supplied" | "capability_self_test_snapshot";
  checkedAt: string | null;
  availability: ReadonlyMap<string, "available" | "unavailable" | "unknown">;
}> {
  const configured = process.env.TI_SCALE_KALI_RUNTIME_READINESS_PATH?.trim();
  if (!configured) {
    return Object.freeze({
      source: "not_supplied" as const,
      checkedAt: null,
      availability: new Map(),
    });
  }
  if (!configured.startsWith("/")) {
    throw new Error("TI_SCALE_KALI_RUNTIME_READINESS_PATH must be absolute");
  }
  const snapshot = parseCapabilitySelfTestSnapshot(
    JSON.parse(boundedRead(configured, MAX_RUNTIME_READINESS_BYTES).toString("utf8")) as unknown,
  );
  const canonical = snapshot.accounting.runtimeRegistryRead
    && snapshot.accounting.manifestValid
    && snapshot.accounting.complete;
  const availability = new Map<string, "available" | "unavailable" | "unknown">();
  for (const result of snapshot.results.filter(({ component }) => component.kind === "tool")) {
    const expiry = result.freshness.expiresAt === null
      ? Number.NaN
      : Date.parse(result.freshness.expiresAt);
    const fresh = result.freshness.state === "fresh"
      && Number.isFinite(expiry)
      && expiry > now.getTime();
    availability.set(result.component.id, canonical
      && result.status === "pass"
      && result.availability === "available"
      && fresh
      ? "available"
      : "unavailable");
  }
  return Object.freeze({
    source: "capability_self_test_snapshot" as const,
    checkedAt: snapshot.checkedAt,
    availability,
  });
}

function main(): void {
  const now = new Date();
  const manifest = loadTrustedLocalToolCapabilityManifest({
    path: MANIFEST_PATH,
    trustRoot: SOURCE_ROOT,
    expectedSha256: MANIFEST_SHA256,
    allowedOwnerUids: [0],
  }).value;
  const runtimeReadiness = runtimeAvailabilityByTool(now);
  const policyDefinitions = new Map(ACTION_CLASS_DEFINITIONS.map((entry) => [entry.id, entry]));
  const aliasRecords = aliases();
  const inspections = new Map(aliasRecords.map((entry) => [entry.alias, inspect(entry.alias)]));
  const projection = projectInstalledKaliToolInventory({
    aliases: aliasRecords.map((entry) => ({
      ...entry,
      actionClassId: POLICY_CLASS_BY_ALIAS[entry.alias]!,
    })),
    inspections: new Map([...inspections].map(([alias, inspected]) => [
      alias,
      inspected === null
        ? null
        : {
            resolvedPath: inspected.resolvedPath,
            sha256: inspected.sha256,
            uid: inspected.uid,
            mode: inspected.mode,
            serviceUserExecutable: inspected.serviceUserExecutable,
            fileCapabilities: inspected.fileCapabilities,
          } satisfies InstalledKaliExecutableInspection,
    ])),
    reviewedRoutes: manifest.list().map((tool) => ({
      toolId: tool.toolId,
      executablePath: tool.executable.path,
      expectedSha256: tool.executable.expectedSha256,
      actionClassIds: tool.actionClassIds,
      runtimeAvailability: runtimeReadiness.availability.get(tool.toolId) ?? "unknown",
    })),
  });
  const records = projection.tools.map((entry) => {
    const inspected = inspections.get(entry.alias) ?? null;
    const actionClassId = POLICY_CLASS_BY_ALIAS[entry.alias]!;
    const definition = policyDefinitions.get(actionClassId)!;
    return Object.freeze({
      ...entry,
      riskBand: definition.riskBand,
      platformDefaultPolicy: definition.defaultPolicyState,
      destructiveOrDisruptive: definition.destructiveOrDisruptive,
      inspected,
      requiredActivationDependencies: REQUIRED_ACTIVATION_DEPENDENCIES,
    });
  });
  const report = Object.freeze({
    schemaVersion: "ti-scale.installed-kali-tool-activation-audit.v2",
    readOnly: true,
    targetInteraction: false,
    grantsMissionExecution: false,
    source: ALIAS_INVENTORY,
    canonicalReviewedManifestVersion: manifest.descriptor.manifestVersion,
    runtimeReadiness: Object.freeze({
      source: runtimeReadiness.source,
      checkedAt: runtimeReadiness.checkedAt,
      semantics: runtimeReadiness.source === "not_supplied"
        ? "Configured routes remain unknown and are never labelled ready."
        : "Only fresh passing canonical tool self-tests are labelled runtime-ready.",
    }),
    accounting: Object.freeze({
      ...projection.accounting,
      present: records.filter(({ inspected }) => inspected !== null).length,
      structurallyExecutableAsServiceUser: records.filter(({ inspected }) => inspected?.serviceUserExecutable).length,
    }),
    runtimeRoutesWithoutAliasMatch: projection.runtimeRoutesWithoutAliasMatch,
    tools: Object.freeze(records),
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (import.meta.main) main();
