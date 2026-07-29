import type {
  CapabilityAvailability,
  CapabilityFreshnessState,
  CapabilitySelfTestComponentKind,
  CapabilitySelfTestKind,
  CapabilitySelfTestResult,
  CapabilitySelfTestSnapshot,
  CapabilitySelfTestStatus,
} from "../types/capabilitySelfTests";

type UnknownRecord = Record<string, unknown>;

const COMPONENT_KINDS = new Set<CapabilitySelfTestComponentKind>([
  "registry", "database", "event_stream", "second_brain", "obsidian_vault",
  "provider", "mcp_server", "tool", "tool_dependency",
]);
const TEST_KINDS = new Set<CapabilitySelfTestKind>([
  "manifest_integrity", "local_integrity", "service_state", "canonical_read",
  "vault_round_trip_receipt", "runtime_attestation", "local_executable_attestation",
  "manifest_dependency",
]);
const STATUSES = new Set<CapabilitySelfTestStatus>(["pass", "degraded", "fail"]);
const AVAILABILITY = new Set<CapabilityAvailability>(["available", "degraded", "unavailable", "unsupported"]);
const FRESHNESS = new Set<CapabilityFreshnessState>(["fresh", "stale", "unknown"]);

function object(value: unknown, label: string): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as UnknownRecord;
}

function exact(value: unknown, label: string, keys: readonly string[]): UnknownRecord {
  const item = object(value, label);
  const expected = new Set(keys);
  for (const key of Object.keys(item)) if (!expected.has(key)) throw new Error(`${label} contains unsupported field ${key}`);
  for (const key of keys) if (!Object.prototype.hasOwnProperty.call(item, key)) throw new Error(`${label} is missing ${key}`);
  return item;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function timestamp(value: unknown, label: string): string {
  const result = text(value, label);
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO timestamp`);
  return result;
}

function nullableTimestamp(value: unknown, label: string): string | null {
  return value === null ? null : timestamp(value, label);
}

function bool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

function count(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative integer`);
  return value;
}

function nullableCount(value: unknown, label: string): number | null {
  return value === null ? null : count(value, label);
}

function enumValue<T extends string>(value: unknown, values: ReadonlySet<T>, label: string): T {
  const result = text(value, label) as T;
  if (!values.has(result)) throw new Error(`${label} is invalid`);
  return result;
}

function counts(value: unknown, label: string): CapabilitySelfTestSnapshot["accounting"]["registered"] {
  const item = exact(value, label, ["providers", "mcpServers", "tools", "toolDependencies"]);
  return {
    providers: count(item.providers, `${label}.providers`),
    mcpServers: count(item.mcpServers, `${label}.mcpServers`),
    tools: count(item.tools, `${label}.tools`),
    toolDependencies: count(item.toolDependencies, `${label}.toolDependencies`),
  };
}

function parseResult(value: unknown, index: number): CapabilitySelfTestResult {
  const label = `capability self-test result ${index + 1}`;
  const item = exact(value, label, [
    "id", "component", "testKind", "status", "availability", "checkedAt",
    "freshness", "explanation", "remediation", "executionAuthorization",
  ]);
  const component = exact(item.component, `${label}.component`, ["kind", "id", "label"]);
  const freshness = exact(item.freshness, `${label}.freshness`, ["state", "observedAt", "expiresAt", "maximumAgeMs"]);
  const authorization = exact(item.executionAuthorization, `${label}.executionAuthorization`, [
    "state", "grantsMissionExecution", "explanation",
  ]);
  if (authorization.state !== "not_granted" || authorization.grantsMissionExecution !== false) {
    throw new Error(`${label} must not grant mission execution`);
  }
  const remediation = item.remediation === null ? null : text(item.remediation, `${label}.remediation`);
  return {
    id: text(item.id, `${label}.id`),
    component: {
      kind: enumValue(component.kind, COMPONENT_KINDS, `${label}.component.kind`),
      id: text(component.id, `${label}.component.id`),
      label: text(component.label, `${label}.component.label`),
    },
    testKind: enumValue(item.testKind, TEST_KINDS, `${label}.testKind`),
    status: enumValue(item.status, STATUSES, `${label}.status`),
    availability: enumValue(item.availability, AVAILABILITY, `${label}.availability`),
    checkedAt: timestamp(item.checkedAt, `${label}.checkedAt`),
    freshness: {
      state: enumValue(freshness.state, FRESHNESS, `${label}.freshness.state`),
      observedAt: nullableTimestamp(freshness.observedAt, `${label}.freshness.observedAt`),
      expiresAt: nullableTimestamp(freshness.expiresAt, `${label}.freshness.expiresAt`),
      maximumAgeMs: nullableCount(freshness.maximumAgeMs, `${label}.freshness.maximumAgeMs`),
    },
    explanation: text(item.explanation, `${label}.explanation`),
    remediation,
    executionAuthorization: {
      state: "not_granted",
      grantsMissionExecution: false,
      explanation: text(authorization.explanation, `${label}.executionAuthorization.explanation`),
    },
  };
}

export function parseCapabilitySelfTestSnapshot(value: unknown): CapabilitySelfTestSnapshot {
  const root = exact(value, "capability self-test snapshot", [
    "schemaVersion", "checkedAt", "readOnly", "grantsMissionExecution", "accounting", "summary", "results",
  ]);
  if (root.schemaVersion !== "2.4") throw new Error("unsupported Ti-Scale schema version");
  if (root.readOnly !== true || root.grantsMissionExecution !== false) {
    throw new Error("capability self-test snapshot must be read-only and non-authorizing");
  }
  const accounting = exact(root.accounting, "capability self-test accounting", [
    "runtimeRegistryRead", "manifestValid", "complete", "registered", "reported",
  ]);
  const summary = exact(root.summary, "capability self-test summary", [
    "total", "pass", "degraded", "fail", "available", "degradedAvailability", "unavailable", "unsupported",
  ]);
  if (!Array.isArray(root.results)) throw new Error("capability self-test results must be an array");
  const results = root.results.map(parseResult);
  if (new Set(results.map((result) => result.id)).size !== results.length) {
    throw new Error("capability self-test result identifiers must be unique");
  }
  const parsedSummary = {
    total: count(summary.total, "capability self-test summary.total"),
    pass: count(summary.pass, "capability self-test summary.pass"),
    degraded: count(summary.degraded, "capability self-test summary.degraded"),
    fail: count(summary.fail, "capability self-test summary.fail"),
    available: count(summary.available, "capability self-test summary.available"),
    degradedAvailability: count(summary.degradedAvailability, "capability self-test summary.degradedAvailability"),
    unavailable: count(summary.unavailable, "capability self-test summary.unavailable"),
    unsupported: count(summary.unsupported, "capability self-test summary.unsupported"),
  };
  const measured = {
    pass: results.filter((result) => result.status === "pass").length,
    degraded: results.filter((result) => result.status === "degraded").length,
    fail: results.filter((result) => result.status === "fail").length,
    available: results.filter((result) => result.availability === "available").length,
    degradedAvailability: results.filter((result) => result.availability === "degraded").length,
    unavailable: results.filter((result) => result.availability === "unavailable").length,
    unsupported: results.filter((result) => result.availability === "unsupported").length,
  };
  if (
    parsedSummary.total !== results.length
    || parsedSummary.pass + parsedSummary.degraded + parsedSummary.fail !== results.length
    || parsedSummary.available + parsedSummary.degradedAvailability + parsedSummary.unavailable + parsedSummary.unsupported !== results.length
    || Object.entries(measured).some(([key, value]) => parsedSummary[key as keyof typeof parsedSummary] !== value)
  ) throw new Error("capability self-test summary does not reconcile with its results");
  const registered = counts(accounting.registered, "capability accounting.registered");
  const reported = counts(accounting.reported, "capability accounting.reported");
  const complete = bool(accounting.complete, "capability accounting.complete");
  if (complete && Object.keys(registered).some((key) =>
    registered[key as keyof typeof registered] !== reported[key as keyof typeof reported])) {
    throw new Error("complete capability accounting does not reconcile registered and reported counts");
  }
  return {
    schemaVersion: "2.4",
    checkedAt: timestamp(root.checkedAt, "capability self-test checkedAt"),
    readOnly: true,
    grantsMissionExecution: false,
    accounting: {
      runtimeRegistryRead: bool(accounting.runtimeRegistryRead, "capability accounting.runtimeRegistryRead"),
      manifestValid: bool(accounting.manifestValid, "capability accounting.manifestValid"),
      complete,
      registered,
      reported,
    },
    summary: parsedSummary,
    results,
  };
}
