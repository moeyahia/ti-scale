import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { SqliteDatabase } from "../../db";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  agentAssignmentBindsRuntimeAgent,
  canonicalProductOwnerBindsRuntimeAgent,
} from "../RuntimeAgentAssignmentBinding";

const PRODUCT_AGENT_ID = "ReconScout";
const RUNTIME_AGENT_ID = "specialist:autonomous-safe-recon";
const NOW = "2026-07-23T14:00:00.000Z";

describe("product-agent runtime assignment binding", () => {
  let database: SqliteDatabase;

  beforeEach(() => {
    database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const insert = database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, provider_policy_json, tool_policy_json,
        configuration_json, version, last_heartbeat_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, '{}', '{}', ?, 'test-v1', ?, ?, ?)
    `);
    insert.run(
      RUNTIME_AGENT_ID,
      "runtime-adapter",
      "Internal Safe Recon adapter",
      "available",
      JSON.stringify({ internalComponent: true }),
      NOW,
      NOW,
      NOW,
    );
    insert.run(
      PRODUCT_AGENT_ID,
      "reconnaissance",
      "ReconScout",
      "available",
      JSON.stringify({
        userFacing: true,
        productAgent: true,
        runtimeBindingAgentIds: [RUNTIME_AGENT_ID],
      }),
      NOW,
      NOW,
      NOW,
    );
    insert.run(
      "Commander",
      "planning",
      "Commander",
      "available",
      JSON.stringify({
        userFacing: true,
        productAgent: true,
        orchestrationAgent: true,
        executionAuthority: "none",
        runtimeBindingAgentIds: [],
      }),
      NOW,
      NOW,
      NOW,
    );
  });

  afterEach(() => database.close());

  test("accepts a canonical product owner only for its exact executable runtime binding", () => {
    expect(agentAssignmentBindsRuntimeAgent(
      database,
      PRODUCT_AGENT_ID,
      RUNTIME_AGENT_ID,
    )).toBeTrue();
    expect(agentAssignmentBindsRuntimeAgent(
      database,
      PRODUCT_AGENT_ID,
      "specialist:unrelated",
    )).toBeFalse();
  });

  test("fails closed when either projected side is unavailable or malformed", () => {
    database.prepare("UPDATE agents SET status = 'offline' WHERE id = ?")
      .run(RUNTIME_AGENT_ID);
    expect(agentAssignmentBindsRuntimeAgent(
      database,
      PRODUCT_AGENT_ID,
      RUNTIME_AGENT_ID,
    )).toBeFalse();

    database.prepare("UPDATE agents SET status = 'available' WHERE id = ?")
      .run(RUNTIME_AGENT_ID);
    database.prepare("UPDATE agents SET configuration_json = '{}' WHERE id = ?")
      .run(PRODUCT_AGENT_ID);
    expect(agentAssignmentBindsRuntimeAgent(
      database,
      PRODUCT_AGENT_ID,
      RUNTIME_AGENT_ID,
    )).toBeFalse();
  });

  test("preserves an exact direct runtime assignment for compatibility", () => {
    expect(agentAssignmentBindsRuntimeAgent(
      database,
      RUNTIME_AGENT_ID,
      RUNTIME_AGENT_ID,
    )).toBeTrue();
  });

  test("requires the signed durable owner of the action class before accepting its runtime adapter", () => {
    const canonical = {
      actionClassId: "port_service_enumeration",
      planAgentId: PRODUCT_AGENT_ID,
      assignmentAgentId: PRODUCT_AGENT_ID,
      signedSpecialistAgentIds: [PRODUCT_AGENT_ID, "WebBreaker"],
      runtimeAgentId: RUNTIME_AGENT_ID,
    } as const;
    expect(canonicalProductOwnerBindsRuntimeAgent(database, canonical)).toBeTrue();
    expect(canonicalProductOwnerBindsRuntimeAgent(database, {
      ...canonical,
      planAgentId: "WebBreaker",
      assignmentAgentId: "WebBreaker",
    })).toBeFalse();
    expect(canonicalProductOwnerBindsRuntimeAgent(database, {
      ...canonical,
      signedSpecialistAgentIds: [RUNTIME_AGENT_ID],
    })).toBeFalse();
    expect(canonicalProductOwnerBindsRuntimeAgent(database, {
      ...canonical,
      actionClassId: "unregistered_test_action",
    })).toBeFalse();
    expect(canonicalProductOwnerBindsRuntimeAgent(database, {
      ...canonical,
      planAgentId: "Commander",
      assignmentAgentId: "Commander",
      signedSpecialistAgentIds: ["Commander"],
    })).toBeFalse();
    expect(agentAssignmentBindsRuntimeAgent(
      database,
      "Commander",
      RUNTIME_AGENT_ID,
    )).toBeFalse();
  });
});
