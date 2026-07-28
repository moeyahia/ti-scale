import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { MissionIntakeService } from "../../../server/intake";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { completeRuntimeManifests } from "../../unit/domain/fixtures";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";
import type { AutonomousBranchFixture } from "./autonomousBranchFixture";

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return E2E_DATABASE_PATH;
}

function seedAutonomousBranchFixture(instanceId: string): AutonomousBranchFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const observedAt = "2026-07-17T07:00:00.000Z";
  const baseRuntimeManifests = completeRuntimeManifests();
  const runtimeManifests = {
    ...baseRuntimeManifests,
    providers: baseRuntimeManifests.providers.map((provider) => ({
      ...provider,
      catalogObservedAt: observedAt,
    })),
  };
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const resolved = new MissionIntakeService({
      readRuntimeManifests: () => runtimeManifests,
      clock: () => new Date(observedAt),
    }).resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.129.39.191" }],
      environmentClassification: "htb",
      templateId: "safe_recon",
      title: `Autonomous branch contract ${namespace}`,
      objective: "Validate a versioned successor contract using only runtime-derived structured policy controls.",
    });
    const request = validateMissionCreateRequest(resolved.request);
    if (request.journey !== "autonomous") throw new Error("Expected an Autonomous branch fixture request");
    if (request.contract.allowedActionClasses.length === 0) {
      throw new Error("The Autonomous branch fixture must resolve at least one runtime-supported action class");
    }
    const created = inImmediateTransaction(database, () => {
      const mission = new MissionRepository(database).create({
        request,
        requestHash: hashCanonical(request),
        idempotencyKey: `autonomous-branch-contract-e2e-${namespace}`,
        actorId: `e2e-branch-operator-${namespace}`,
      });
      const completedAt = "2026-07-17T07:05:00.000Z";
      database.prepare(`
        UPDATE runs SET status = 'completed', progress = 1,
          status_reason = 'Completed autonomously for structured branch-contract coverage.',
          next_action_summary = 'Create a separate versioned run when needed.',
          ended_at = ?, updated_at = ?, version = version + 1 WHERE id = ?
      `).run(completedAt, completedAt, mission.run.id);
      database.prepare(`
        UPDATE missions SET status = 'completed', updated_at = ? WHERE id = ?
      `).run(completedAt, mission.mission.id);
      return mission;
    });
    return { missionId: created.mission.id, runId: created.run.id };
  } finally {
    database.close();
  }
}

try {
  const instanceId = process.argv[2];
  if (!instanceId) throw new Error("The Autonomous branch fixture seed requires an instance identifier");
  console.log(JSON.stringify({ fixture: seedAutonomousBranchFixture(instanceId) }));
} catch (error) {
  console.log(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
}
