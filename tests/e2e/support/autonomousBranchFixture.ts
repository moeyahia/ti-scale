import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { E2E_DATABASE_PATH } from "./environment";

export interface AutonomousBranchFixture {
  readonly missionId: string;
  readonly runId: string;
}

interface SeedResponse {
  readonly fixture?: AutonomousBranchFixture;
  readonly error?: string;
}

const seedEntry = fileURLToPath(new URL("./autonomousBranchFixtureSeed.ts", import.meta.url));

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return E2E_DATABASE_PATH;
}

function isFixture(value: unknown): value is AutonomousBranchFixture {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.missionId === "string"
    && record.missionId.length > 0
    && typeof record.runId === "string"
    && record.runId.length > 0;
}

/**
 * Keep the Playwright worker on its supported Node runtime while seeding the
 * isolated fixture through the same Bun SQLite adapter as the application.
 */
export function createAutonomousBranchFixture(instanceId: string): AutonomousBranchFixture {
  const result = spawnSync(
    process.env.TI_SCALE_BUN_EXECUTABLE?.trim() || "bun",
    ["run", seedEntry, instanceId],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        TI_SCALE_E2E_DATABASE_PATH: databasePath(),
      },
      maxBuffer: 1024 * 1024,
      timeout: 120_000,
    },
  );
  if (result.error) {
    throw new Error(`Autonomous branch fixture seed could not start: ${result.error.message}`);
  }
  if (result.signal) {
    throw new Error(`Autonomous branch fixture seed was terminated by ${result.signal}`);
  }
  const output = result.stdout.trim();
  let response: SeedResponse;
  try {
    response = JSON.parse(output) as SeedResponse;
  } catch {
    throw new Error(
      `Autonomous branch fixture seed returned invalid JSON (exit ${String(result.status)}): ${output || result.stderr.trim()}`,
    );
  }
  if (result.status !== 0 || response.error) {
    throw new Error(
      `Autonomous branch fixture seed failed (exit ${String(result.status)}): ${response.error ?? result.stderr.trim()}`,
    );
  }
  if (!isFixture(response.fixture)) {
    throw new Error("Autonomous branch fixture seed did not return stable mission and run identifiers");
  }
  return response.fixture;
}
