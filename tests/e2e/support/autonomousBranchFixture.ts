import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { MissionIntakeService } from "../../../server/intake";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { completeRuntimeManifests } from "../../unit/domain/fixtures";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export interface AutonomousBranchFixture {
  readonly missionId: string;
  readonly runId: string;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return E2E_DATABASE_PATH;
}

export function createAutonomousBranchFixture(instanceId: string): AutonomousBranchFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const resolved = new MissionIntakeService({
      // Strict Autonomous creation must be backed by an attested, locally
      // enforced execution path. The fail-closed empty-manifest default is
      // appropriate for product code, but it cannot create this executable
      // branch-contract fixture.
      readRuntimeManifests: () => completeRuntimeManifests(),
      clock: () => new Date("2026-07-17T07:00:00.000Z"),
    }).resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: `lab:branch-contract-${namespace}` }],
      templateId: "safe_recon",
      title: `Autonomous branch contract ${namespace}`,
      objective: "Validate a versioned successor contract using only runtime-derived structured policy controls.",
    });
    const request = validateMissionCreateRequest(resolved.request);
    if (request.journey !== "autonomous") throw new Error("Expected an Autonomous branch fixture request");
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
