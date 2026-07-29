import { basename } from "node:path";
import type { ActionClassId } from "../domain";

export const INSTALLED_KALI_TOOL_INVENTORY_SCHEMA_VERSION =
  "ti-scale.installed-kali-tool-inventory.v2" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;

export type InstalledKaliToolInstallationState =
  | "missing"
  | "service_user_unavailable"
  | "executable_trust_conflict"
  | "inspection_incomplete"
  | "no_new_privileges_conflict"
  | "installed_runnable";

export type InstalledKaliToolActivationState =
  | "runtime_ready_exact_binding"
  | "runtime_ready_reviewed_alternative"
  | "reviewed_binding_not_ready"
  | "reviewed_alternative_not_ready"
  | "adapter_review_required"
  | "installation_blocked";

export type InstalledKaliToolBlocker =
  | "executable_missing"
  | "service_user_cannot_execute"
  | "executable_ownership_or_mode_unreviewed"
  | "file_capability_inspection_unavailable"
  | "no_new_privileges_file_capability_conflict"
  | "not_in_canonical_runtime_registry"
  | "missing_pinned_argument_schema"
  | "missing_target_free_probe_receipt"
  | "missing_workspace_result_and_cancellation_receipts"
  | "reviewed_runtime_receipt_unavailable";

export interface InstalledKaliAliasDefinition {
  readonly section: string;
  readonly alias: string;
  readonly declaredTool: string;
  readonly actionClassId: ActionClassId;
}

export interface InstalledKaliExecutableInspection {
  readonly resolvedPath: string;
  readonly sha256: string;
  readonly uid: number;
  readonly mode: number;
  readonly serviceUserExecutable: boolean;
  /** `none` is an observed empty getcap result; null means inspection failed. */
  readonly fileCapabilities: string | null;
}

export interface InstalledKaliReviewedRoute {
  readonly toolId: string;
  readonly executablePath: string;
  readonly expectedSha256: string;
  readonly actionClassIds: readonly ActionClassId[];
  /** Only a fresh canonical runtime projection may claim `available`. */
  readonly runtimeAvailability: "available" | "unavailable" | "unknown";
}

export interface InstalledKaliToolInventoryRecord extends InstalledKaliAliasDefinition {
  readonly installationState: InstalledKaliToolInstallationState;
  readonly activationState: InstalledKaliToolActivationState;
  readonly directAliasExecutionReady: boolean;
  readonly missionCapabilityReady: boolean;
  readonly reviewedToolId: string | null;
  readonly reviewedRouteKind: "exact_binding" | "reviewed_alternative" | null;
  readonly blockers: readonly InstalledKaliToolBlocker[];
}

export interface InstalledKaliToolInventorySnapshot {
  readonly schemaVersion: typeof INSTALLED_KALI_TOOL_INVENTORY_SCHEMA_VERSION;
  readonly readOnly: true;
  readonly targetInteraction: false;
  readonly grantsMissionExecution: false;
  readonly accounting: Readonly<{
    readonly aliases: number;
    readonly installedRunnable: number;
    readonly missing: number;
    readonly serviceUserUnavailable: number;
    readonly privilegeConflicts: number;
    readonly trustConflicts: number;
    readonly inspectionIncomplete: number;
    readonly runtimeReadyExactBindings: number;
    readonly runtimeReadyReviewedAlternatives: number;
    readonly reviewedBindingsNotReady: number;
    readonly reviewedAlternativesNotReady: number;
    readonly adapterReviewRequired: number;
    readonly installationBlocked: number;
    readonly reviewedRoutes: number;
    readonly runtimeReadyRoutes: number;
    readonly runtimeRoutesWithoutAliasMatch: number;
  }>;
  readonly tools: readonly InstalledKaliToolInventoryRecord[];
  readonly runtimeRoutesWithoutAliasMatch: readonly string[];
}

function validateAliases(aliases: readonly InstalledKaliAliasDefinition[]): void {
  if (aliases.length < 1 || aliases.length > 512) {
    throw new Error("Installed Kali inventory must contain one to 512 aliases");
  }
  const seen = new Set<string>();
  for (const entry of aliases) {
    if (!PUBLIC_ID.test(entry.alias) || entry.alias !== entry.alias.trim()) {
      throw new Error("Installed Kali inventory contains an invalid alias");
    }
    if (seen.has(entry.alias)) throw new Error(`Installed Kali inventory contains duplicate alias ${entry.alias}`);
    seen.add(entry.alias);
    if (!entry.section.trim() || !entry.declaredTool.trim()) {
      throw new Error(`Installed Kali alias ${entry.alias} requires a section and declared tool`);
    }
  }
}

function validateRoutes(routes: readonly InstalledKaliReviewedRoute[]): void {
  const seen = new Set<string>();
  for (const route of routes) {
    if (!PUBLIC_ID.test(route.toolId) || route.toolId !== route.toolId.trim()) {
      throw new Error("Installed Kali inventory contains an invalid reviewed tool ID");
    }
    if (seen.has(route.toolId)) throw new Error(`Installed Kali inventory contains duplicate reviewed route ${route.toolId}`);
    seen.add(route.toolId);
    if (!route.executablePath.startsWith("/") || !SHA256.test(route.expectedSha256)) {
      throw new Error(`Reviewed route ${route.toolId} has an invalid executable identity`);
    }
  }
}

function installationState(
  inspection: InstalledKaliExecutableInspection | null,
): InstalledKaliToolInstallationState {
  if (!inspection) return "missing";
  if (!inspection.serviceUserExecutable) return "service_user_unavailable";
  if (inspection.uid !== 0
    || (inspection.mode & 0o022) !== 0
    || (inspection.mode & 0o7000) !== 0) return "executable_trust_conflict";
  if (inspection.fileCapabilities === null) return "inspection_incomplete";
  if (inspection.fileCapabilities !== "none") return "no_new_privileges_conflict";
  return "installed_runnable";
}

function matchingRoutes(
  alias: InstalledKaliAliasDefinition,
  inspection: InstalledKaliExecutableInspection | null,
  routes: readonly InstalledKaliReviewedRoute[],
): Readonly<{
  exact: InstalledKaliReviewedRoute | undefined;
  alternative: InstalledKaliReviewedRoute | undefined;
}> {
  const applicable = routes
    .filter((route) => route.actionClassIds.includes(alias.actionClassId))
    .sort((left, right) => left.toolId.localeCompare(right.toolId));
  const exact = inspection
    ? applicable.find((route) => route.executablePath === inspection.resolvedPath
      && route.expectedSha256 === inspection.sha256)
    : undefined;
  if (exact) return { exact, alternative: undefined };

  // A basename match is only an explanation that a separately reviewed route
  // implements the same named tool. It never promotes the installed alias and
  // still requires an action-class match and a fresh canonical runtime receipt.
  const declaredExecutable = basename(alias.declaredTool.trim());
  const alternative = applicable.find((route) => basename(route.executablePath) === declaredExecutable);
  return { exact: undefined, alternative };
}

function integrationBlockers(): readonly InstalledKaliToolBlocker[] {
  return [
    "not_in_canonical_runtime_registry",
    "missing_pinned_argument_schema",
    "missing_target_free_probe_receipt",
    "missing_workspace_result_and_cancellation_receipts",
  ];
}

function installationBlockers(
  inspection: InstalledKaliExecutableInspection | null,
): readonly InstalledKaliToolBlocker[] {
  if (!inspection) return ["executable_missing"];
  const blockers: InstalledKaliToolBlocker[] = [];
  if (!inspection.serviceUserExecutable) blockers.push("service_user_cannot_execute");
  if (inspection.uid !== 0
    || (inspection.mode & 0o022) !== 0
    || (inspection.mode & 0o7000) !== 0) {
    blockers.push("executable_ownership_or_mode_unreviewed");
  }
  if (inspection.fileCapabilities === null) blockers.push("file_capability_inspection_unavailable");
  else if (inspection.fileCapabilities !== "none") {
    blockers.push("no_new_privileges_file_capability_conflict");
  }
  return blockers;
}

function classifyRecord(
  alias: InstalledKaliAliasDefinition,
  inspection: InstalledKaliExecutableInspection | null,
  routes: readonly InstalledKaliReviewedRoute[],
): InstalledKaliToolInventoryRecord {
  const installed = installationState(inspection);
  const matches = matchingRoutes(alias, inspection, routes);
  const route = matches.exact ?? matches.alternative;
  const routeKind = matches.exact
    ? "exact_binding" as const
    : matches.alternative
      ? "reviewed_alternative" as const
      : null;
  const routeReady = route?.runtimeAvailability === "available";
  const directAliasExecutionReady = installed === "installed_runnable"
    && routeKind === "exact_binding"
    && routeReady;
  const missionCapabilityReady = routeReady
    && (routeKind === "reviewed_alternative" || installed === "installed_runnable");

  let activationState: InstalledKaliToolActivationState;
  if (directAliasExecutionReady) activationState = "runtime_ready_exact_binding";
  else if (routeKind === "reviewed_alternative" && routeReady) {
    activationState = "runtime_ready_reviewed_alternative";
  } else if (routeKind === "exact_binding") activationState = "reviewed_binding_not_ready";
  else if (routeKind === "reviewed_alternative") activationState = "reviewed_alternative_not_ready";
  else if (installed === "installed_runnable") activationState = "adapter_review_required";
  else activationState = "installation_blocked";

  const blockers = [...installationBlockers(inspection)];
  if (!route) blockers.push(...integrationBlockers());
  else if (!routeReady) blockers.push("reviewed_runtime_receipt_unavailable");

  return Object.freeze({
    ...alias,
    installationState: installed,
    activationState,
    directAliasExecutionReady,
    missionCapabilityReady,
    reviewedToolId: route?.toolId ?? null,
    reviewedRouteKind: routeKind,
    blockers: Object.freeze(blockers),
  });
}

/**
 * Reconciles the installed alias inventory with reviewed runtime routes on two
 * independent axes. Installed/runnable never means activated, and an active
 * capability-free alternative never conceals a conflict on the original
 * alias. The function is read-only and grants no execution authority.
 */
export function projectInstalledKaliToolInventory(input: Readonly<{
  aliases: readonly InstalledKaliAliasDefinition[];
  inspections: ReadonlyMap<string, InstalledKaliExecutableInspection | null>;
  reviewedRoutes: readonly InstalledKaliReviewedRoute[];
}>): InstalledKaliToolInventorySnapshot {
  validateAliases(input.aliases);
  validateRoutes(input.reviewedRoutes);
  const aliasIds = new Set(input.aliases.map(({ alias }) => alias));
  const unexpected = [...input.inspections.keys()].filter((alias) => !aliasIds.has(alias));
  if (unexpected.length > 0) {
    throw new Error(`Installed Kali inspection contains unexpected alias ${unexpected.sort()[0]}`);
  }

  const tools = input.aliases
    .map((alias) => classifyRecord(alias, input.inspections.get(alias.alias) ?? null, input.reviewedRoutes))
    .sort((left, right) => left.alias.localeCompare(right.alias));
  const matchedRouteIds = new Set(tools
    .map(({ reviewedToolId }) => reviewedToolId)
    .filter((toolId): toolId is string => toolId !== null));
  const runtimeRoutesWithoutAliasMatch = input.reviewedRoutes
    .filter(({ toolId }) => !matchedRouteIds.has(toolId))
    .map(({ toolId }) => toolId)
    .sort((left, right) => left.localeCompare(right));

  return Object.freeze({
    schemaVersion: INSTALLED_KALI_TOOL_INVENTORY_SCHEMA_VERSION,
    readOnly: true,
    targetInteraction: false,
    grantsMissionExecution: false,
    accounting: Object.freeze({
      aliases: tools.length,
      installedRunnable: tools.filter(({ installationState: state }) => state === "installed_runnable").length,
      missing: tools.filter(({ installationState: state }) => state === "missing").length,
      serviceUserUnavailable: tools.filter(({ installationState: state }) => state === "service_user_unavailable").length,
      privilegeConflicts: tools.filter(({ installationState: state }) => state === "no_new_privileges_conflict").length,
      trustConflicts: tools.filter(({ installationState: state }) => state === "executable_trust_conflict").length,
      inspectionIncomplete: tools.filter(({ installationState: state }) => state === "inspection_incomplete").length,
      runtimeReadyExactBindings: tools.filter(({ activationState: state }) => state === "runtime_ready_exact_binding").length,
      runtimeReadyReviewedAlternatives: tools.filter(({ activationState: state }) => state === "runtime_ready_reviewed_alternative").length,
      reviewedBindingsNotReady: tools.filter(({ activationState: state }) => state === "reviewed_binding_not_ready").length,
      reviewedAlternativesNotReady: tools.filter(({ activationState: state }) => state === "reviewed_alternative_not_ready").length,
      adapterReviewRequired: tools.filter(({ activationState: state }) => state === "adapter_review_required").length,
      installationBlocked: tools.filter(({ activationState: state }) => state === "installation_blocked").length,
      reviewedRoutes: input.reviewedRoutes.length,
      runtimeReadyRoutes: input.reviewedRoutes.filter(({ runtimeAvailability }) => runtimeAvailability === "available").length,
      runtimeRoutesWithoutAliasMatch: runtimeRoutesWithoutAliasMatch.length,
    }),
    tools: Object.freeze(tools),
    runtimeRoutesWithoutAliasMatch: Object.freeze(runtimeRoutesWithoutAliasMatch),
  });
}
