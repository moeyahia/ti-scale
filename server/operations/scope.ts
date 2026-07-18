import { OperationsApiError } from "./errors";
import type { OperationsAccessPolicy, OperationsSensitivity } from "./types";
import { identifier } from "./validation";

const SENSITIVITY_ORDER: readonly OperationsSensitivity[] = [
  "public",
  "internal",
  "private",
  "restricted",
];

export function validateAccessPolicy(access: OperationsAccessPolicy): void {
  if (!SENSITIVITY_ORDER.includes(access.maximumSensitivity)) {
    throw new OperationsApiError(500, "invalid_access_policy", "Operations access policy is invalid", {
      humanMessage: "The server produced an invalid operations access policy.",
      category: "configuration",
    });
  }
  for (const value of [...(access.engagementIds ?? []), ...(access.missionIds ?? [])]) {
    identifier(value, "Access scope identifier");
  }
}

/** SQL predicate for a query that already joins `missions` as the supplied alias. */
export function missionScopeSql(
  alias: string,
  access: OperationsAccessPolicy,
): { readonly sql: string; readonly params: readonly unknown[] } {
  if (access.allEngagements) return { sql: "1", params: [] };
  const clauses: string[] = [];
  const params: unknown[] = [];
  const missionIds = [...new Set(access.missionIds ?? [])];
  const engagementIds = [...new Set(access.engagementIds ?? [])];
  if (missionIds.length > 0) {
    clauses.push(`${alias}.id IN (${missionIds.map(() => "?").join(",")})`);
    params.push(...missionIds);
  }
  if (engagementIds.length > 0) {
    clauses.push(`${alias}.engagement_id IN (${engagementIds.map(() => "?").join(",")})`);
    params.push(...engagementIds);
  }
  return { sql: clauses.length > 0 ? `(${clauses.join(" OR ")})` : "0", params };
}

export function sensitivitySql(
  expression: string,
  access: OperationsAccessPolicy,
): { readonly sql: string; readonly params: readonly OperationsSensitivity[] } {
  const maximum = SENSITIVITY_ORDER.indexOf(access.maximumSensitivity);
  const visible = SENSITIVITY_ORDER.slice(0, maximum + 1);
  return {
    sql: `${expression} IN (${visible.map(() => "?").join(",")})`,
    params: visible,
  };
}

/** Lessons can be global, engagement-scoped, or attached to a scoped mission. */
export function lessonScopeSql(
  alias: string,
  access: OperationsAccessPolicy,
): { readonly sql: string; readonly params: readonly unknown[] } {
  if (access.allEngagements && access.allowGlobalKnowledge !== false) {
    return { sql: "1", params: [] };
  }
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (access.allowGlobalKnowledge) {
    clauses.push(`(${alias}.engagement_id IS NULL AND ${alias}.mission_id IS NULL)`);
  }
  const engagements = [...new Set(access.engagementIds ?? [])];
  if (access.allEngagements) {
    clauses.push(`${alias}.engagement_id IS NOT NULL`);
  } else if (engagements.length > 0) {
    clauses.push(`${alias}.engagement_id IN (${engagements.map(() => "?").join(",")})`);
    params.push(...engagements);
  }
  const missions = [...new Set(access.missionIds ?? [])];
  if (access.allEngagements) {
    clauses.push(`${alias}.mission_id IS NOT NULL`);
  } else if (missions.length > 0) {
    clauses.push(`${alias}.mission_id IN (${missions.map(() => "?").join(",")})`);
    params.push(...missions);
  }
  return { sql: clauses.length > 0 ? `(${clauses.join(" OR ")})` : "0", params };
}
