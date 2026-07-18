import { getDatabaseHealth } from "../db";
import type { SqliteDatabase } from "../db";
import type {
  Journey,
  ReadinessCheck,
  ReadinessCheckProvider,
  ReadinessContext,
  ReadinessSummary,
} from "./types";

function normalizedCheck(check: ReadinessCheck): ReadinessCheck {
  const id = check.id.trim();
  const label = check.label.trim();
  const impact = check.impact.trim();
  const journeys = [...new Set(check.journeys)];
  if (!id || !label || !impact) throw new Error("Readiness checks require id, label, and impact");
  if (check.status !== "pass" && check.status !== "warn" && check.status !== "fail") {
    throw new Error(`Readiness check ${id} has an invalid status`);
  }
  if (journeys.length === 0) throw new Error(`Readiness check ${id} has no journey scope`);
  if (journeys.some((journey) => journey !== "autonomous" && journey !== "guided")) {
    throw new Error(`Readiness check ${id} has an invalid journey scope`);
  }
  return {
    id,
    label,
    impact,
    status: check.status,
    journeys,
    ...(check.remediation?.trim() ? { remediation: check.remediation.trim() } : {}),
  };
}

function summary(checks: readonly ReadinessCheck[]): ReadinessSummary {
  const status = checks.length === 0
    ? "blocked"
    : checks.some((check) => check.status === "fail")
    ? "blocked"
    : checks.some((check) => check.status === "warn")
      ? "degraded"
      : "ready";
  const points = checks.reduce(
    (total, check) => total + (check.status === "pass" ? 100 : check.status === "warn" ? 65 : 0),
    0,
  );
  return {
    status,
    score: checks.length === 0 ? 0 : Math.round(points / checks.length),
    checks,
  };
}

/**
 * Aggregates concrete readiness providers. Providers own the actual connection,
 * policy, credential, or capability checks; this service never invents a pass.
 */
export class ReadinessService {
  constructor(private readonly providers: readonly ReadinessCheckProvider[]) {
    if (providers.length === 0) {
      throw new Error("At least one real readiness check provider is required");
    }
    const ids = new Set<string>();
    for (const provider of providers) {
      const id = provider.id.trim();
      if (!id || ids.has(id)) throw new Error(`Invalid or duplicate readiness provider: ${id}`);
      if (provider.journeys.length === 0) {
        throw new Error(`Readiness provider ${id} has no journey scope`);
      }
      ids.add(id);
    }
    for (const journey of ["autonomous", "guided"] as const) {
      if (!providers.some((provider) => provider.journeys.includes(journey))) {
        throw new Error(`No real readiness provider covers the ${journey} journey`);
      }
    }
  }

  async evaluate(context: ReadinessContext = {}): Promise<ReadinessSummary> {
    const checks: ReadinessCheck[] = [];
    for (const provider of this.providers) {
      try {
        const result = await provider.evaluate(context);
        const values = Array.isArray(result) ? result : [result];
        if (values.length === 0) throw new Error("Readiness provider returned no checks");
        for (const value of values) checks.push(normalizedCheck(value));
      } catch {
        checks.push({
          id: provider.id,
          label: provider.label,
          status: "fail",
          journeys: provider.journeys,
          impact: "The readiness check could not complete, so execution capability is unverified.",
          remediation: "Inspect the affected connection or policy service and run readiness again.",
        });
      }
    }

    const unique = new Map<string, ReadinessCheck>();
    for (const check of checks) {
      if (unique.has(check.id)) throw new Error(`Duplicate readiness check ID: ${check.id}`);
      unique.set(check.id, check);
    }
    return summary([...unique.values()]);
  }

  async evaluateJourney(
    journey: Journey,
    context: Omit<ReadinessContext, "journey"> = {},
  ): Promise<ReadinessSummary> {
    const all = await this.evaluate({ ...context, journey });
    return summary(all.checks.filter((check) => check.journeys.includes(journey)));
  }
}

/** A concrete local-database provider suitable for the router dependency list. */
export function createDatabaseReadinessProvider(
  database: SqliteDatabase,
): ReadinessCheckProvider {
  return {
    id: "database",
    label: "Canonical database",
    journeys: ["autonomous", "guided"],
    evaluate(): ReadinessCheck {
      const health = getDatabaseHealth(database);
      return health.healthy
        ? {
            id: "database",
            label: "Canonical database",
            status: "pass",
            journeys: ["autonomous", "guided"],
            impact: `SQLite integrity and foreign keys are healthy at schema version ${health.currentMigration}.`,
          }
        : {
            id: "database",
            label: "Canonical database",
            status: "fail",
            journeys: ["autonomous", "guided"],
            impact: "Mission state cannot be committed safely because database integrity is degraded.",
            remediation: "Run the database integrity and migration verification before launching a mission.",
          };
    },
  };
}
