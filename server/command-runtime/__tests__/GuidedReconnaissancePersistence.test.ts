import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { hashCanonical } from "../../missions/canonical";
import { MissionRepository } from "../../missions/MissionRepository";
import type { GuidedMissionRequest } from "../../missions/types";
import { RuntimeRepository } from "../RuntimeRepository";

describe("Guided reconnaissance persistence", () => {
  test("omits an unselected reconnaissance mode and tolerates the preview null representation", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const request: GuidedMissionRequest = {
        journey: "guided",
        launch: true,
        authorizationConfirmed: true,
        title: "Target-derived Guided baseline",
        objective: "Represent one safe first step for the authorized target",
        target: "127.0.0.1",
        explanationDepth: "balanced",
        executionPreference: "manual",
        evidenceExpectations: [],
      };
      const created = new MissionRepository(database).create({
        request,
        requestHash: hashCanonical(request),
        idempotencyKey: "guided-recon-absent-0001",
        actorId: "operator:test",
      });
      const stored = database.prepare(`
        SELECT value_json FROM mission_constraints
        WHERE mission_id = ? AND constraint_type = 'guided_collaboration'
      `).get(created.mission.id) as { value_json: string };
      expect(JSON.parse(stored.value_json)).not.toHaveProperty("guidedReconnaissance");
      expect(new RuntimeRepository(database).getMission(created.mission.id).guidedReconnaissance)
        .toBeUndefined();

      database.prepare(`
        UPDATE mission_constraints SET value_json = json_set(value_json, '$.guidedReconnaissance', NULL)
        WHERE mission_id = ? AND constraint_type = 'guided_collaboration'
      `).run(created.mission.id);
      expect(new RuntimeRepository(database).getMission(created.mission.id).guidedReconnaissance)
        .toBeUndefined();
    } finally {
      database.close();
    }
  });

  test("round-trips the normalized selection through the canonical mission constraint", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const request: GuidedMissionRequest = {
        journey: "guided",
        launch: true,
        authorizationConfirmed: true,
        title: "Focused service baseline",
        objective: "Identify selected services on the authorized host",
        target: "10.10.10.20",
        explanationDepth: "balanced",
        executionPreference: "single_step_agent",
        evidenceExpectations: ["port_service_scan_result"],
        guidedReconnaissance: {
          mode: "tcp_service_scan",
          portSelection: {
            source: "preset",
            presetId: "focused_services",
            presetVersion: 1,
            ports: [22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443],
          },
        },
      };
      const created = new MissionRepository(database).create({
        request,
        requestHash: hashCanonical(request),
        idempotencyKey: "guided-recon-persistence-0001",
        actorId: "operator:test",
      });
      const stored = database.prepare(`
        SELECT value_json FROM mission_constraints
        WHERE mission_id = ? AND constraint_type = 'guided_collaboration'
      `).get(created.mission.id) as { value_json: string };
      expect(JSON.parse(stored.value_json)).toMatchObject({ guidedReconnaissance: request.guidedReconnaissance });

      const projected = new RuntimeRepository(database).getMission(created.mission.id);
      expect(projected.executionPreference).toBe("single_step_agent");
      expect(projected.guidedReconnaissance).toEqual(request.guidedReconnaissance);
    } finally {
      database.close();
    }
  });

  test("fails closed instead of silently reverting to target-derived routing when the stored selection is corrupt", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const request: GuidedMissionRequest = {
        journey: "guided",
        launch: true,
        authorizationConfirmed: true,
        title: "Corruption boundary",
        objective: "Prove the persisted first-step boundary",
        target: "10.10.10.21",
        explanationDepth: "balanced",
        executionPreference: "single_step_agent",
        evidenceExpectations: [],
        guidedReconnaissance: { mode: "host_liveness" },
      };
      const created = new MissionRepository(database).create({
        request,
        requestHash: hashCanonical(request),
        idempotencyKey: "guided-recon-corruption-0001",
        actorId: "operator:test",
      });
      database.prepare(`
        UPDATE mission_constraints SET value_json = ?
        WHERE mission_id = ? AND constraint_type = 'guided_collaboration'
      `).run(JSON.stringify({
        explanationDepth: "balanced",
        executionPreference: "single_step_agent",
        evidenceExpectations: [],
        guidedReconnaissance: {
          mode: "tcp_service_scan",
          portSelection: { source: "custom", ports: ["1-65535"] },
        },
      }), created.mission.id);
      expect(() => new RuntimeRepository(database).getMission(created.mission.id)).toThrow(
        "stored Guided reconnaissance selection failed canonical validation",
      );
    } finally {
      database.close();
    }
  });
});
