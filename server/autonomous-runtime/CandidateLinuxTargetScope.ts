import { isIP } from "node:net";

export const CANDIDATE_LINUX_TARGET_SCOPE_SCHEMA_VERSION =
  "ti-scale.candidate-linux-target-scope.v1" as const;

export type CandidateLinuxTargetScope = Readonly<{
  readonly schemaVersion:
    typeof CANDIDATE_LINUX_TARGET_SCOPE_SCHEMA_VERSION;
  readonly kind: "exact_target" | "all_authorized_ip_targets";
  /**
   * The canonical IP copied from mission authorization and the represented
   * action. It is null only for a provider that was explicitly reviewed for
   * every authorized IP target.
   */
  readonly exactTarget: string | null;
  /**
   * An optional endpoint compiled into the provider. Runtime requests still
   * carry only the canonical IP; the separately hash-pinned provider owns this
   * closed endpoint and cannot accept a caller-selected port.
   */
  readonly endpoint: Readonly<{
    readonly transport: "tcp";
    readonly port: number;
  }> | null;
  /**
   * This is intentionally independent from the legacy realTargetSupport
   * discriminator. Only the explicit all-authorized-IP scope may advertise
   * global mission readiness.
   */
  readonly generalMissionReadinessEligible: boolean;
}>;

function plain(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (
    actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])
  ) {
    throw new TypeError(`${label} must contain exactly: ${canonical.join(", ")}`);
  }
}

function canonicalIp(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || value !== value.trim()
    || isIP(value) === 0
  ) {
    throw new TypeError(`${label} must be one canonical IP literal`);
  }
  return value;
}

export function parseCandidateLinuxTargetScope(
  value: unknown,
): CandidateLinuxTargetScope {
  const scope = plain(value, "candidate Linux target scope");
  exactKeys(scope, [
    "endpoint",
    "exactTarget",
    "generalMissionReadinessEligible",
    "kind",
    "schemaVersion",
  ], "candidate Linux target scope");
  if (
    scope.schemaVersion !== CANDIDATE_LINUX_TARGET_SCOPE_SCHEMA_VERSION
    || (
      scope.kind !== "exact_target"
      && scope.kind !== "all_authorized_ip_targets"
    )
  ) {
    throw new TypeError("Candidate Linux target scope is unsupported");
  }

  if (scope.kind === "all_authorized_ip_targets") {
    if (
      scope.exactTarget !== null
      || scope.endpoint !== null
      || scope.generalMissionReadinessEligible !== true
    ) {
      throw new TypeError(
        "All-authorized-IP scope must explicitly grant general readiness without an endpoint override",
      );
    }
    return Object.freeze({
      schemaVersion: CANDIDATE_LINUX_TARGET_SCOPE_SCHEMA_VERSION,
      kind: "all_authorized_ip_targets",
      exactTarget: null,
      endpoint: null,
      generalMissionReadinessEligible: true,
    });
  }

  const exactTarget = canonicalIp(
    scope.exactTarget,
    "candidate Linux target scope exactTarget",
  );
  let endpoint: CandidateLinuxTargetScope["endpoint"] = null;
  if (scope.endpoint !== null) {
    const rawEndpoint = plain(
      scope.endpoint,
      "candidate Linux target scope endpoint",
    );
    exactKeys(
      rawEndpoint,
      ["port", "transport"],
      "candidate Linux target scope endpoint",
    );
    if (
      rawEndpoint.transport !== "tcp"
      || !Number.isSafeInteger(rawEndpoint.port)
      || Number(rawEndpoint.port) < 1
      || Number(rawEndpoint.port) > 65_535
    ) {
      throw new TypeError(
        "Candidate Linux target endpoint must be one valid TCP port",
      );
    }
    endpoint = Object.freeze({
      transport: "tcp",
      port: Number(rawEndpoint.port),
    });
  }
  if (scope.generalMissionReadinessEligible !== false) {
    throw new TypeError(
      "An exact-target provider cannot advertise general mission readiness",
    );
  }
  return Object.freeze({
    schemaVersion: CANDIDATE_LINUX_TARGET_SCOPE_SCHEMA_VERSION,
    kind: "exact_target",
    exactTarget,
    endpoint,
    generalMissionReadinessEligible: false,
  });
}

export function exactCandidateLinuxTargetScope(
  exactTarget: string,
  endpoint: Readonly<{ transport: "tcp"; port: number }> | null = null,
): CandidateLinuxTargetScope {
  return parseCandidateLinuxTargetScope({
    schemaVersion: CANDIDATE_LINUX_TARGET_SCOPE_SCHEMA_VERSION,
    kind: "exact_target",
    exactTarget,
    endpoint,
    generalMissionReadinessEligible: false,
  });
}

export function allAuthorizedIpCandidateLinuxTargetScope(): CandidateLinuxTargetScope {
  return parseCandidateLinuxTargetScope({
    schemaVersion: CANDIDATE_LINUX_TARGET_SCOPE_SCHEMA_VERSION,
    kind: "all_authorized_ip_targets",
    exactTarget: null,
    endpoint: null,
    generalMissionReadinessEligible: true,
  });
}

export function candidateLinuxTargetScopeMatches(
  scope: CandidateLinuxTargetScope,
  exactTarget: string,
): boolean {
  if (isIP(exactTarget) === 0 || exactTarget !== exactTarget.trim()) {
    return false;
  }
  return scope.kind === "all_authorized_ip_targets"
    ? true
    : scope.exactTarget === exactTarget;
}

export function candidateLinuxTargetScopesEqual(
  left: CandidateLinuxTargetScope,
  right: CandidateLinuxTargetScope,
): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.kind === right.kind
    && left.exactTarget === right.exactTarget
    && left.generalMissionReadinessEligible
      === right.generalMissionReadinessEligible
    && left.endpoint?.transport === right.endpoint?.transport
    && left.endpoint?.port === right.endpoint?.port;
}

export function candidateLinuxTargetScopeLabel(
  scope: CandidateLinuxTargetScope,
): string {
  if (scope.kind === "all_authorized_ip_targets") {
    return "every explicitly authorized IP target";
  }
  if (!scope.endpoint) return scope.exactTarget!;
  const host = isIP(scope.exactTarget!) === 6
    ? `[${scope.exactTarget}]`
    : scope.exactTarget;
  return `${host}:${scope.endpoint.port}`;
}

export function candidateLinuxTargetScopesCover(
  scopes: readonly CandidateLinuxTargetScope[],
  authorizedTargets: readonly string[],
): boolean {
  return scopes.length > 0
    && authorizedTargets.length > 0
    && authorizedTargets.every((target) =>
      scopes.some((scope) => candidateLinuxTargetScopeMatches(scope, target)));
}
