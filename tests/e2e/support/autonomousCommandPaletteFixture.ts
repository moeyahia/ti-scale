import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction, type SqliteDatabase } from "../../../server/db";
import { EventRepository } from "../../../server/events";
import { MissionIntakeService } from "../../../server/intake";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { completeRuntimeManifests } from "../../unit/domain/fixtures";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export interface AutonomousCommandPaletteFixture {
  readonly missionId: string;
  readonly runId: string;
  readonly missionLabel: string;
  readonly missionToken: string;
  readonly runToken: string;
}

function database(): SqliteDatabase {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

function token(namespace: string, purpose: string): string {
  return `autopal${purpose}${createHash("sha256")
    .update(`${namespace}:${purpose}`, "utf8")
    .digest("hex")
    .slice(0, 12)}`;
}

export function autonomousCommandPaletteReservedTarget(instanceId: string): string {
  const namespace = normalizeFixtureNamespace(instanceId);
  return `${token(namespace, "target")}.invalid`;
}

function representedAction(target: string): string {
  return JSON.stringify({
    action: {
      actionType: "inspect_authorized_domain_dns",
      actionClass: "dns_domain_certificate_discovery",
      target,
      arguments: { readOnly: true },
      intentSummary: "Inspect one exact authorized domain through the signed read-only DNS class without contacting it.",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    explanation: "Represent the reserved domain through the exact DNS discovery class selected by production intake.",
    rationale: "The bounded fixture proves stable search and deep-link behavior without executing the represented action.",
    reversibility: "Read-only",
    dependencies: [],
  });
}

/**
 * Creates one minimal Autonomous mission through the production intake and
 * repository boundary. The fixture writes only to the process-owned E2E
 * database, proves both records are V2 controlled, and never executes the
 * represented action or contacts its standards-reserved `.invalid` domain.
 */
export function createAutonomousCommandPaletteFixture(
  instanceId: string,
): AutonomousCommandPaletteFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const missionToken = token(namespace, "mission");
  const runToken = token(namespace, "run");
  const missionLabel = `Autonomous palette beacon ${token(namespace, "label")}`;
  const now = new Date().toISOString();
  const connection = database();
  try {
    const resolved = new MissionIntakeService({
      readRuntimeManifests: () => completeRuntimeManifests({ catalogObservedAt: now }),
      clock: () => new Date(now),
    }).resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: autonomousCommandPaletteReservedTarget(namespace) }],
      templateId: "safe_recon",
      title: missionLabel,
      objective: "Validate bounded Autonomous search and navigation without changing authorization or contacting a target.",
    });
    const request = validateMissionCreateRequest(resolved.request);
    if (request.journey !== "autonomous") throw new Error("Expected an Autonomous palette fixture request");
    const expectedActionClasses = ["dns_domain_certificate_discovery"];
    if (JSON.stringify(request.contract.allowedActionClasses) !== JSON.stringify(expectedActionClasses)) {
      throw new Error(
        `Expected the production intake boundary to resolve exactly ${expectedActionClasses.join(", ")}; received ${request.contract.allowedActionClasses.join(", ") || "none"}`,
      );
    }
    const created = new MissionRepository(connection).create({
      request,
      requestHash: hashCanonical(request),
      idempotencyKey: `autonomous-command-palette-e2e-${namespace}`,
      actorId: `e2e-autonomous-palette-operator-${namespace}`,
    });
    const missionId = created.mission.id;
    const runId = created.run.id;
    const agentId = `agent-${runToken}`;
    const planId = `plan-autonomous-palette-${namespace}`;
    const stepId = `step-autonomous-palette-${namespace}`;
    const target = request.authorization.allowedTargets[0]!;

    inImmediateTransaction(connection, () => {
      connection.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (?, 'recon-specialist', 'Autonomous palette recon specialist', 'available',
          '{}', '{}', '{}', 'e2e-2.4', ?, ?, ?)
      `).run(agentId, now, now, now);
      connection.prepare(`
        INSERT INTO agent_capabilities (
          agent_id, capability, source, enabled, metadata_json
        ) VALUES (?, 'dns.recon', 'runtime', 1, '{}')
      `).run(agentId);
      connection.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, rationale_summary,
          plan_hash, created_by, created_at, activated_at
        ) VALUES (?, ?, 1, 'active', 'Bounded Autonomous palette search',
          'Keep the signed contract and one-control-plane boundary intact', ?,
          'e2e-runtime-planner', ?, ?)
      `).run(
        planId,
        runId,
        createHash("sha256").update(`${planId}:v1`, "utf8").digest("hex"),
        now,
        now,
      );
      connection.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, created_at, updated_at
        ) VALUES (?, ?, ?, 0, ?, 'Inspect represented Autonomous fixture',
          'Collect one attributable local-fixture observation', 'ready',
          '["The stable Autonomous record remains attributable"]', '[]',
          'dns_domain_certificate_discovery', 'low', ?, ?, ?)
      `).run(stepId, planId, runId, missionToken, agentId, now, now);
      connection.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (?, ?, 'represented_action', ?, ?, ?)
      `).run(
        `constraint-autonomous-palette-${namespace}`,
        missionId,
        representedAction(target),
        stepId,
        now,
      );
      connection.prepare(`
        INSERT INTO assignments (
          id, run_id, step_id, agent_id, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'queued', ?, ?)
      `).run(`assignment-autonomous-palette-${namespace}`, runId, stepId, agentId, now, now);
      const updated = connection.prepare(`
        UPDATE runs SET current_plan_id = ?, current_step_id = ?, current_owner_id = ?,
          next_action_summary = 'Inspect the represented read-only Autonomous fixture',
          updated_at = ?
        WHERE id = ? AND journey = 'autonomous' AND control_plane = 'ti_scale'
      `).run(planId, stepId, agentId, now, runId);
      if (updated.changes !== 1) throw new Error("Could not bind the V2-owned Autonomous palette run");

      const ownership = connection.prepare(`
        SELECT m.control_plane AS mission_control_plane, r.control_plane AS run_control_plane
        FROM missions m JOIN runs r ON r.mission_id = m.id
        WHERE m.id = ? AND r.id = ?
      `).get(missionId, runId) as {
        mission_control_plane: string;
        run_control_plane: string;
      } | undefined;
      if (ownership?.mission_control_plane !== "ti_scale" || ownership.run_control_plane !== "ti_scale") {
        throw new Error("The Autonomous palette fixture is outside the V2 control plane");
      }
      new EventRepository(connection).append({
        missionId,
        runId,
        journey: "autonomous",
        eventType: "plan.activated",
        actorType: "system",
        actorId: "e2e-runtime-planner",
        summary: "The bounded Autonomous fixture plan was activated inside the signed contract",
        payload: { planId, stepId, controlPlane: "ti_scale", targetInteraction: false },
      });
    });

    return { missionId, runId, missionLabel, missionToken, runToken };
  } finally {
    connection.close();
  }
}
