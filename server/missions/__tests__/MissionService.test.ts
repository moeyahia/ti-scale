import { describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { RuntimeSourceManifests } from "../../domain";
import {
  BrainContextHookError,
  BrainContextService,
  type BrainDependencyAvailability,
} from "../../brain-runtime";
import { MemoryRepository, SecondBrainService, type MemoryNodeType, type MemoryScope } from "../../memory";
import {
  AutonomousReadinessError,
  IdempotencyConflictError,
  MissionRepository,
  MissionService,
  MissionValidationError,
  OverviewRepository,
  ReadinessService,
  validateMissionCreateRequest,
  type AutonomousMissionRequest,
  type GuidedMissionRequest,
  type ReadinessCheckProvider,
} from "../index";

function autonomousRequest(overrides: Partial<AutonomousMissionRequest> = {}): AutonomousMissionRequest {
  return {
    journey: "autonomous",
    launch: true,
    title: "Authorized service assessment",
    objective: "Validate exposed services within the signed lab scope",
    successCriteria: ["Every approved target has evidence-backed service inventory"],
    authorization: {
      engagementId: "engagement-lab",
      allowedTargets: ["10.10.10.0/24"],
      prohibitedTargets: ["10.10.10.1"],
      authorizationConfirmed: true,
      timeWindow: "2026-07-15T00:00:00Z/2026-07-16T00:00:00Z",
      dataHandling: "Keep evidence local",
    },
    contract: {
      allowedActionClasses: ["reconnaissance"],
      prohibitedActionClasses: ["destructive"],
      destructivePolicy: "prohibited",
      evidenceRequirements: ["Hash every retained artifact"],
      timeBudgetMinutes: 60,
      toolCallBudget: 100,
      tokenBudget: 50_000,
      costBudget: 10,
      retryBudget: 2,
      replanBudget: 2,
      concurrencyLimit: 3,
      evidenceStorageBudgetBytes: 64 * 1024 * 1024,
      artifactStorageBudgetBytes: 256 * 1024 * 1024,
      notificationPolicy: "in_app_only",
      reportingFormat: "ti_scale_json",
      dataHandlingPolicy: "local_private",
      retentionPolicy: "operator_managed",
      providerPolicy: "automatic_enforcing_only",
      toolPolicy: "contract_allowlist",
      specialistAgentIds: ["agent-recon"],
      memoryScopes: ["verified_lessons"],
      contextNodeIds: [],
      safeStopConditions: ["Target resolves outside approved scope"],
      deliverables: ["Evidence-backed mission report"],
    },
    ...overrides,
  };
}

function guidedRequest(overrides: Partial<GuidedMissionRequest> = {}): GuidedMissionRequest {
  return {
    journey: "guided",
    launch: true,
    authorizationConfirmed: true,
    title: "Guided lab assessment",
    objective: "Understand the authorized service exposure one step at a time",
    target: "lab.internal",
    engagementId: "engagement-lab",
    explanationDepth: "deep",
    executionPreference: "manual",
    evidenceExpectations: ["Retain normalized scan output"],
    ...overrides,
  };
}

function provider(
  status: "pass" | "warn" | "fail" = "pass",
  id = "runtime-enforcement",
): ReadinessCheckProvider {
  return {
    id,
    label: "Runtime enforcement",
    journeys: ["autonomous", "guided"],
    evaluate: () => ({
      id,
      label: "Runtime enforcement",
      status,
      journeys: ["autonomous", "guided"],
      impact: status === "pass" ? "Policy boundary is enforceable." : "Policy boundary is unavailable.",
      ...(status === "fail" ? { remediation: "Restore the enforcing runtime." } : {}),
    }),
  };
}

function service(
  database: ReturnType<typeof createDatabaseConnection>,
  readinessProviders: readonly ReadinessCheckProvider[] = [provider()],
  brainAvailability?: () => BrainDependencyAvailability,
  readRuntimeManifests?: () => RuntimeSourceManifests,
): MissionService {
  const now = new Date().toISOString();
  const validUntil = new Date(Date.now() + 5 * 60_000).toISOString();
  database.prepare(`
    INSERT OR IGNORE INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES ('agent-recon', 'reconnaissance', 'Recon specialist', 'available',
      '{"defaultProvider":"xai-grok-oauth"}',
      '{"allowedTools":["nmap"],"deniedTools":[],"approvalRequiredTools":[]}',
      '{}', '2.4', ?, ?, ?)
  `).run(now, now, now);
  database.prepare(`
    INSERT OR IGNORE INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    ) VALUES ('agent-recon', 'nmap', 'live-route-attestation', 1, ?)
  `).run(JSON.stringify({ validUntil, attestedAt: now, providerIds: ["xai-grok-oauth"] }));
  database.prepare(`
    INSERT OR IGNORE INTO mcp_servers (
      id, name, transport, endpoint_redacted, status, capabilities_json,
      policy_json, last_checked_at, created_at, updated_at
    ) VALUES ('mcp:nmap', 'nmap', 'stdio', 'local stdio', 'healthy', '["nmap"]',
      '{"enabled":true,"assignedAgents":["agent-recon"],"startPermitted":true,"riskClass":"medium"}',
      ?, ?, ?)
  `).run(now, now, now);
  database.prepare(`
    INSERT INTO health_snapshots (
      id, component_type, component_id, status, metrics_json, message, captured_at
    ) VALUES (?, 'provider', 'xai-grok-oauth', 'healthy',
      ?,
      'OAuth and Autonomous boundary verified', ?)
  `).run(`health-${randomUUID()}`, JSON.stringify({
    authenticated: true,
    callable: true,
    attestedAt: now,
    expiresAt: validUntil,
    enforcesAutonomousBoundary: true,
    reportsExactTokenUsage: true,
    reportsExactCostUsage: true,
  }), now);
  return new MissionService(
    new MissionRepository(database),
    new OverviewRepository(database),
    new ReadinessService(readinessProviders),
    new BrainContextService({
      database,
      secondBrain: new SecondBrainService(new MemoryRepository(database)),
      ...(brainAvailability ? { availability: brainAvailability } : {}),
    }),
    readRuntimeManifests,
  );
}

function evidenceRuntimeManifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [
      {
        id: "scan-evidence-producer",
        label: "Available scan evidence producer",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: false,
        actionClassIds: [],
        evidenceTypeIds: ["port_service_scan_result"],
        riskClassIds: [],
      },
      {
        id: "dns-evidence-producer",
        label: "Unavailable DNS evidence producer",
        available: false,
        locallyPolicyEnforced: true,
        requiresModel: false,
        actionClassIds: [],
        evidenceTypeIds: ["dns_certificate_record"],
        riskClassIds: [],
      },
    ],
    mcpServers: [],
    agents: [],
    providers: [],
  };
}

function count(database: ReturnType<typeof createDatabaseConnection>, table: string): number {
  return (database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}

function memoryNode(
  database: ReturnType<typeof createDatabaseConnection>,
  input: { id: string; nodeType: MemoryNodeType; scope: MemoryScope; status: "confirmed" | "verified" },
): void {
  new MemoryRepository(database).createNode({
    id: input.id,
    nodeType: input.nodeType,
    title: `${input.nodeType} ${input.id}`,
    summary: `Canonical ${input.status} context`,
    scope: input.scope,
    sensitivity: "private",
    confidence: 0.9,
    lifecycleStatus: input.status,
    confirmationState: input.nodeType === "preference" ? "confirmed" : "not_required",
    provenance: {
      method: "operator_statement",
      explanation: "Confirmed in the focused contract test",
      sources: [{ sourceType: "test", sourceId: input.id, acquiredAt: new Date().toISOString() }],
    },
    authorType: "operator",
    retentionPolicy: { allowAutonomous: true },
  });
}

describe("Ti-Scale mission vertical slice", () => {
  test("accepts exactly Autonomous and Guided as journeys", () => {
    expect(() =>
      validateMissionCreateRequest({
        ...guidedRequest(),
        journey: "ask",
      }),
    ).toThrow(MissionValidationError);
    expect(() =>
      validateMissionCreateRequest({
        ...guidedRequest(),
        journey: "supervised",
      }),
    ).toThrow(MissionValidationError);
    expect(validateMissionCreateRequest(guidedRequest()).journey).toBe("guided");
    expect(validateMissionCreateRequest(autonomousRequest()).journey).toBe("autonomous");
  });

  test("requires an explicit authorization assertion for Guided creation", () => {
    expect(() => validateMissionCreateRequest({
      ...guidedRequest(),
      authorizationConfirmed: false,
    })).toThrow(MissionValidationError);
  });

  test("rejects incomplete Autonomous authority, scope, action policy, budgets, and deliverables", () => {
    expect(() =>
      validateMissionCreateRequest({
        ...autonomousRequest(),
        authorization: {
          allowedTargets: [],
          prohibitedTargets: [],
          authorizationConfirmed: false,
        },
        contract: {
          ...autonomousRequest().contract,
          allowedActionClasses: [],
          timeBudgetMinutes: 0,
          concurrencyLimit: 0,
          safeStopConditions: [],
          deliverables: [],
        },
      }),
    ).toThrow(MissionValidationError);
  });

  test("accepts only closed destructive-action policy values", () => {
    const validated = validateMissionCreateRequest(autonomousRequest({
      contract: { ...autonomousRequest().contract, destructivePolicy: "validate_without_executing" },
    }));
    expect(validated.journey).toBe("autonomous");
    if (validated.journey !== "autonomous") throw new Error("Expected an Autonomous request");
    expect(validated.contract.destructivePolicy).toBe("validate_without_executing");
    const bounded = validateMissionCreateRequest(autonomousRequest({
      contract: {
        ...autonomousRequest().contract,
        destructivePolicy: "bounded_lab_only",
        boundedDestructiveTargets: ["10.10.10.0/24"],
      },
    }));
    expect(bounded.journey === "autonomous" && bounded.contract.boundedDestructiveTargets).toEqual(["10.10.10.0/24"]);
    expect(() => validateMissionCreateRequest(autonomousRequest({
      contract: { ...autonomousRequest().contract, destructivePolicy: "bounded_lab_only" },
    }))).toThrow(MissionValidationError);
    expect(() => validateMissionCreateRequest({
      ...autonomousRequest(),
      contract: { ...autonomousRequest().contract, destructivePolicy: "ask_operator" },
    })).toThrow(MissionValidationError);
  });

  test("rejects cross-engagement memory use without an engagement boundary and canonical target overlap", () => {
    expect(() =>
      validateMissionCreateRequest({
        ...autonomousRequest(),
        authorization: {
          ...autonomousRequest().authorization,
          engagementId: undefined,
        },
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: ["engagement_memory"],
        },
      }),
    ).toThrow(MissionValidationError);
    expect(() =>
      validateMissionCreateRequest({
        ...autonomousRequest(),
        authorization: {
          ...autonomousRequest().authorization,
          allowedTargets: ["HTTP://LAB.INTERNAL"],
          prohibitedTargets: ["http://lab.internal/"],
        },
      }),
    ).toThrow(MissionValidationError);
  });

  test("creates an Autonomous aggregate, confirmed contract, targets, constraints, events, and audit atomically", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const created = await service(database).create(
        autonomousRequest(),
        "autonomous-request-0001",
        "operator-1",
      );
      expect(created.run).toMatchObject({ journey: "autonomous", status: "planning" });
      expect(created.nextUrl).toBe(`/missions/${created.mission.id}`);

      const run = database
        .prepare("SELECT journey, status, contract_id FROM runs WHERE id = ?")
        .get(created.run.id) as { journey: string; status: string; contract_id: string | null };
      expect(run).toMatchObject({ journey: "autonomous", status: "planning" });
      expect(run.contract_id).not.toBeNull();
      expect(count(database, "mission_contracts")).toBe(1);
      expect(count(database, "mission_targets")).toBe(2);
      expect(count(database, "mission_constraints")).toBe(5);
      const persisted = database.prepare(`
        SELECT m.retention_policy_json, m.memory_policy_json,
          mc.contract_hash, mc.action_policy_json, mc.budgets_json,
          r.budget_json AS run_budget_json
        FROM missions m JOIN runs r ON r.mission_id = m.id
        JOIN mission_contracts mc ON mc.id = r.contract_id WHERE r.id = ?
      `).get(created.run.id) as Record<string, string>;
      expect(JSON.parse(persisted.retention_policy_json)).toEqual({
        dataHandling: "local_private",
        mode: "operator_managed",
      });
      expect(JSON.parse(persisted.memory_policy_json)).toMatchObject({ exactContextNodeIds: [] });
      expect(JSON.parse(persisted.action_policy_json)).toMatchObject({
        notificationPolicy: "in_app_only",
        reportingFormat: "ti_scale_json",
        providerPolicy: "automatic_enforcing_only",
        toolPolicy: "contract_allowlist",
        specialistAgentIds: ["agent-recon"],
      });
      expect(JSON.parse(persisted.budgets_json)).toMatchObject({
        toolCalls: 100,
        evidenceBytes: 64 * 1024 * 1024,
        artifactBytes: 256 * 1024 * 1024,
      });
      expect(JSON.parse(persisted.run_budget_json)).toMatchObject({ toolCalls: 100 });
      expect(persisted.contract_hash).toMatch(/^[a-f0-9]{64}$/u);
      expect(count(database, "events")).toBe(2);
      expect(count(database, "event_outbox")).toBe(2);
      expect(count(database, "audit_records")).toBe(2);
      expect(
        database.prepare("SELECT COUNT(*) AS count FROM runs WHERE status = 'waiting_guided_decision'").get(),
      ).toEqual({ count: 0 });
      const journeys = database
        .prepare("SELECT DISTINCT journey FROM events")
        .all() as Array<{ journey: string }>;
      expect(journeys).toEqual([{ journey: "autonomous" }]);
    } finally {
      database.close();
    }
  });

  test("previews and fail-closed validates exact confirmed preferences and verified lessons", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      memoryNode(database, { id: "mem-preference", nodeType: "preference", scope: { kind: "global" }, status: "confirmed" });
      memoryNode(database, { id: "mem-lesson", nodeType: "lesson", scope: { kind: "engagement", engagementId: "engagement-lab" }, status: "verified" });
      memoryNode(database, { id: "mem-cross-scope", nodeType: "lesson", scope: { kind: "engagement", engagementId: "other-engagement" }, status: "verified" });
      const missionService = service(database);
      const requested = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: ["confirmed_preferences", "verified_lessons", "engagement_memory"],
          contextNodeIds: ["mem-preference", "mem-lesson"],
        },
      });
      const preview = await missionService.preflightAutonomous(requested);
      expect(preview.readiness.status).toBe("ready");
      expect(preview.context.candidates.map((candidate) => candidate.id).sort()).toEqual([
        "mem-lesson",
        "mem-preference",
      ]);
      expect(preview.context.selectedNodeIds).toEqual(["mem-preference", "mem-lesson"]);
      expect(preview.context.invalidSelectedNodeIds).toEqual([]);

      const invalid = await missionService.preflightAutonomous({
        ...requested,
        contract: { ...requested.contract, contextNodeIds: ["mem-cross-scope"] },
      });
      expect(invalid.readiness.status).toBe("blocked");
      expect(invalid.context.invalidSelectedNodeIds).toEqual(["mem-cross-scope"]);

      const created = await missionService.create(
        { ...requested, contractReview: preview.contract },
        "exact-memory-contract-001",
        "operator-1",
      );
      expect(created.intakeContext).toMatchObject({
        hook: "intake",
        status: "ready",
        retrievedCount: 2,
        memoryInfluencedDefaults: false,
      });
      const policy = database.prepare(`
        SELECT mc.action_policy_json FROM runs r
        JOIN mission_contracts mc ON mc.id = r.contract_id WHERE r.id = ?
      `).get(created.run.id) as { action_policy_json: string };
      expect(JSON.parse(policy.action_policy_json).contextNodeIds).toEqual(["mem-preference", "mem-lesson"]);
    } finally {
      database.close();
    }
  });

  test("inspects real provider, MCP, and specialist policy then rejects an incompatible signed pool", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database);
      const preview = await missionService.preflightAutonomous(autonomousRequest());
      expect(preview.readiness.status).toBe("ready");
      expect(preview.execution.providers).toEqual([
        expect.objectContaining({
          id: "xai-grok-oauth",
          authenticated: true,
          enforcesAutonomousBoundary: true,
          compatible: true,
        }),
      ]);
      expect(preview.execution.tools).toEqual([
        expect.objectContaining({
          id: "mcp:nmap",
          status: "healthy",
          assignedAgentIds: ["agent-recon"],
          capabilities: ["nmap"],
        }),
      ]);
      expect(preview.execution.team).toMatchObject({
        selectedAgentIds: ["agent-recon"],
        invalidSelectedAgentIds: [],
        effectiveAgentIds: ["agent-recon"],
      });
      expect(preview.execution.team.candidates).toEqual([
        expect.objectContaining({
          id: "agent-recon",
          compatible: true,
          runnableTools: ["nmap"],
          providerPolicy: { defaultProvider: "xai-grok-oauth" },
        }),
      ]);

      const unknown = await missionService.preflightAutonomous(autonomousRequest({
        contract: { ...autonomousRequest().contract, specialistAgentIds: ["agent-unknown"] },
      }));
      expect(unknown.readiness.status).toBe("blocked");
      expect(unknown.contract.hash).not.toBe(preview.contract.hash);
      expect(unknown.execution.team.invalidSelectedAgentIds).toEqual(["agent-unknown"]);
      expect(unknown.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_specialist_selection",
        status: "fail",
      }));

      database.prepare("UPDATE mcp_servers SET status = 'offline' WHERE id = 'mcp:nmap'").run();
      const unavailable = await missionService.preflightAutonomous(autonomousRequest());
      expect(unavailable.readiness.status).toBe("blocked");
      expect(unavailable.execution.team.invalidSelectedAgentIds).toEqual(["agent-recon"]);
      expect(unavailable.execution.team.candidates[0]).toMatchObject({
        compatible: false,
        runnableTools: [],
      });
    } finally {
      database.close();
    }
  });

  test("blocks required evidence that has no available runtime producer without rewriting the draft", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(
        database,
        [provider()],
        undefined,
        evidenceRuntimeManifests,
      );
      const supportedRequest = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          evidenceRequirements: ["port_service_scan_result"],
        },
      });
      const supported = await missionService.preflightAutonomous(supportedRequest);
      expect(supported.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_evidence_capability",
        status: "pass",
      }));

      const impossibleRequest = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          evidenceRequirements: [
            "port_service_scan_result",
            "os_platform_fingerprint",
            "dns_certificate_record",
          ],
        },
      });
      const blocked = await missionService.preflightAutonomous(impossibleRequest);
      expect(blocked.readiness.status).toBe("blocked");
      expect(impossibleRequest.contract.evidenceRequirements).toEqual([
        "port_service_scan_result",
        "os_platform_fingerprint",
        "dns_certificate_record",
      ]);
      expect(blocked.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_evidence_capability",
        status: "fail",
        impact: expect.stringContaining("OS, kernel, or platform fingerprint (unsupported)"),
        remediation: expect.stringContaining("Verified findings still require their immutable evidence"),
      }));
      expect(blocked.readiness.checks.find(({ id }) => id === "contract_evidence_capability")?.impact)
        .toContain("DNS or certificate record (unavailable)");
      await expect(missionService.create(
        { ...impossibleRequest, contractReview: blocked.contract },
        "unsupported-evidence-contract-001",
        "operator-1",
      )).rejects.toBeInstanceOf(AutonomousReadinessError);
    } finally {
      database.close();
    }
  });

  test("excludes approval-required tools from Autonomous readiness and blocks an approval-only specialist", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database);
      database.prepare(`
        UPDATE agents SET tool_policy_json = ? WHERE id = 'agent-recon'
      `).run(JSON.stringify({
        allowedTools: ["nmap"],
        deniedTools: [],
        approvalRequiredTools: ["nmap"],
      }));

      const preview = await missionService.preflightAutonomous(autonomousRequest());
      expect(preview.readiness.status).toBe("blocked");
      expect(preview.execution.tools).toEqual([]);
      expect(preview.execution.team.candidates).toEqual([
        expect.objectContaining({
          id: "agent-recon",
          compatible: false,
          runnableTools: [],
          incompatibilityReasons: [
            "No approval-free reviewed MCP tool binding is available for this tool-requiring contract.",
          ],
          toolPolicy: expect.objectContaining({ approvalRequiredTools: ["nmap"] }),
        }),
      ]);
      expect(preview.execution.team.invalidSelectedAgentIds).toEqual(["agent-recon"]);
      expect(preview.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_specialist_selection",
        status: "fail",
      }));
    } finally {
      database.close();
    }
  });

  test("creates a durable Guided mission without inventing an Autonomous contract", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const created = await service(database).create(
        guidedRequest(),
        "guided-request-0000001",
        "operator-1",
      );
      expect(created.run).toEqual({
        id: created.run.id,
        journey: "guided",
        status: "planning",
      });
      expect(created.nextUrl).toBe(`/guided/${created.mission.id}`);
      expect(count(database, "mission_contracts")).toBe(0);
      expect(count(database, "mission_targets")).toBe(1);
      expect(count(database, "mission_constraints")).toBe(1);
      const mission = database
        .prepare("SELECT authorization_status FROM missions WHERE id = ?")
        .get(created.mission.id) as { authorization_status: string };
      expect(mission.authorization_status).toBe("verified");
    } finally {
      database.close();
    }
  });

  test("retrieves and binds a scope-safe intake Context Pack without claiming it changed defaults", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      new MemoryRepository(database).createNode({
        id: "mem-guided-intake-preference",
        nodeType: "preference",
        title: "Guided lab assessment explanation preference",
        summary: "Use a concise explanation after the operator confirms the preference.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: {
          method: "operator_statement",
          explanation: "Confirmed by the operator in the intake lifecycle fixture.",
          sources: [{ sourceType: "test", sourceId: "guided-intake", acquiredAt: new Date().toISOString() }],
        },
        authorType: "operator",
        authorId: "operator-1",
        retentionPolicy: { allowGuided: true },
      });
      const created = await service(database).create(
        guidedRequest(),
        "guided-intake-context-0001",
        "operator-1",
      );
      expect(created.intakeContext).toMatchObject({
        hook: "intake",
        status: "ready",
        retrievedCount: 1,
        memoryInfluencedDefaults: false,
      });
      if (!created.intakeContext) throw new Error("Expected a durable intake Context Pack binding");
      const policy = database.prepare("SELECT memory_policy_json FROM missions WHERE id = ?")
        .get(created.mission.id) as { memory_policy_json: string };
      expect(JSON.parse(policy.memory_policy_json).intakeContext).toMatchObject({
        contextPackId: created.intakeContext.contextPackId,
        status: "ready",
        memoryInfluencedDefaults: false,
      });
      const disposition = database.prepare(`
        SELECT used, ignored_reason FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = 'mem-guided-intake-preference'
      `).get(created.intakeContext.contextPackId) as { used: number; ignored_reason: string };
      expect(disposition.used).toBe(0);
      expect(disposition.ignored_reason).toContain("defaults remained deterministic");
      const createdEvent = database.prepare(`
        SELECT context_pack_id, payload_json FROM events
        WHERE run_id = ? AND event_type = 'mission.created'
      `).get(created.run.id) as { context_pack_id: string | null; payload_json: string };
      expect(createdEvent.context_pack_id).toBe(created.intakeContext.contextPackId);
      expect(JSON.parse(createdEvent.payload_json).intakeContext).toMatchObject({
        status: "ready",
        memoryInfluencedDefaults: false,
      });
      const missionAudit = database.prepare(`
        SELECT details_json FROM audit_records
        WHERE mission_id = ? AND action = 'mission.created'
      `).get(created.mission.id) as { details_json: string };
      expect(JSON.parse(missionAudit.details_json).intakeContext).toMatchObject({
        contextPackId: created.intakeContext.contextPackId,
        status: "ready",
      });
    } finally {
      database.close();
    }
  });

  test("continues Guided intake with an audited empty degraded Context Pack when the Brain is unavailable", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const created = await service(database, [provider()], () => ({
        available: false,
        code: "brain_offline",
        explanation: "The local Second Brain index is offline.",
      })).create(guidedRequest(), "guided-intake-degraded-0001", "operator-1");
      expect(created.intakeContext).toMatchObject({
        status: "degraded",
        retrievedCount: 0,
        memoryInfluencedDefaults: false,
        degradation: { code: "brain_offline" },
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_context_items WHERE context_pack_id = ?
      `).get(created.intakeContext?.contextPackId)).toEqual({ count: 0 });
      const hookAudit = database.prepare(`
        SELECT details_json FROM audit_records WHERE id = ?
      `).get(created.intakeContext?.auditRecordId) as { details_json: string };
      expect(JSON.parse(hookAudit.details_json)).toMatchObject({
        hook: "intake",
        status: "degraded",
        contextPackId: created.intakeContext?.contextPackId,
        dependencyCode: "brain_offline",
      });
    } finally {
      database.close();
    }
  });

  test("fails a signed-memory Autonomous launch before commit and retains a privacy-safe blocked receipt", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const action = service(database, [provider()], () => ({
        available: false,
        code: "brain_offline",
        explanation: "The local Second Brain index is offline.",
      })).create(autonomousRequest(), "autonomous-intake-required-0001", "operator-1");
      await expect(action).rejects.toBeInstanceOf(BrainContextHookError);
      expect(count(database, "missions")).toBe(0);
      expect(count(database, "runs")).toBe(0);
      expect(count(database, "memory_context_packs")).toBe(0);
      const receipt = database.prepare(`
        SELECT mission_id, run_id, journey, action, resource_type, details_json
        FROM audit_records WHERE action = 'mission.intake_context.blocked'
      `).get() as Record<string, unknown>;
      expect(receipt).toMatchObject({
        mission_id: null,
        run_id: null,
        journey: "autonomous",
        action: "mission.intake_context.blocked",
        resource_type: "mission_intake_request",
      });
      expect(JSON.parse(receipt.details_json as string)).toMatchObject({
        hook: "intake",
        status: "blocked",
        contextPackId: null,
        memoryInfluencedDefaults: false,
      });
    } finally {
      database.close();
    }
  });

  test("persists truthful degraded Autonomous intake when the signed contract selected no memory", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const request = autonomousRequest({
        contract: {
          ...autonomousRequest().contract,
          memoryScopes: [],
          contextNodeIds: [],
        },
      });
      const created = await service(database, [provider()], () => ({
        available: false,
        code: "brain_offline",
        explanation: "The local Second Brain index is offline.",
      })).create(request, "autonomous-intake-empty-0001", "operator-1");
      expect(created.intakeContext).toMatchObject({
        status: "degraded",
        retrievedCount: 0,
        memoryInfluencedDefaults: false,
      });
      expect(created.run.status).toBe("planning");
    } finally {
      database.close();
    }
  });

  test("blocks Autonomous launch on a real failed readiness check without partial writes", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const action = service(database, [provider("fail")]).create(
        autonomousRequest(),
        "blocked-request-00001",
        "operator-1",
      );
      await expect(action).rejects.toBeInstanceOf(AutonomousReadinessError);
      expect(count(database, "missions")).toBe(0);
      expect(count(database, "runs")).toBe(0);
      expect(count(database, "settings")).toBe(0);
    } finally {
      database.close();
    }
  });

  test("replays one successful idempotent mutation and rejects key reuse with a different contract", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      let checks = 0;
      const dynamicProvider: ReadinessCheckProvider = {
        ...provider(),
        evaluate: () => {
          checks += 1;
          return provider(checks === 1 ? "pass" : "fail").evaluate({});
        },
      };
      const missionService = service(database, [dynamicProvider]);
      const first = await missionService.create(
        autonomousRequest(),
        "stable-request-key-001",
        "operator-1",
      );
      const replay = await missionService.create(
        autonomousRequest(),
        "stable-request-key-001",
        "operator-1",
      );
      expect(replay).toEqual(first);
      expect(checks).toBe(1);
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "events")).toBe(2);
      await expect(
        missionService.create(
          autonomousRequest({ title: "Different mission" }),
          "stable-request-key-001",
          "operator-1",
        ),
      ).rejects.toBeInstanceOf(IdempotencyConflictError);
    } finally {
      database.close();
    }
  });

  test("rolls back the entire aggregate when durable event delivery cannot be recorded", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      database.exec(`
        CREATE TRIGGER reject_mission_outbox
        BEFORE INSERT ON event_outbox BEGIN
          SELECT RAISE(ABORT, 'mission outbox unavailable');
        END;
      `);
      await service(database)
        .create(autonomousRequest(), "rollback-request-001", "operator-1")
        .catch((error: unknown) => expect(String(error)).toContain("mission outbox unavailable"));
      for (const table of [
        "missions",
        "runs",
        "mission_targets",
        "mission_constraints",
        "mission_contracts",
        "events",
        "audit_records",
        "settings",
      ]) {
        expect(count(database, table)).toBe(0);
      }
    } finally {
      database.close();
    }
  });

  test("paginates missions with opaque cursors and returns real overview state", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const missionService = service(database, [provider("warn")]);
      await missionService.create(guidedRequest({ title: "Mission A" }), "page-request-0001", "operator");
      await missionService.create(guidedRequest({ title: "Mission B" }), "page-request-0002", "operator");
      await missionService.create(guidedRequest({ title: "Mission C" }), "page-request-0003", "operator");

      const first = missionService.list({ limit: 2 });
      expect(first.items).toHaveLength(2);
      expect(first.nextCursor).not.toBeNull();
      const second = missionService.list({ limit: 2, cursor: first.nextCursor! });
      expect(second.items).toHaveLength(1);
      expect(second.nextCursor).toBeNull();
      expect(new Set([...first.items, ...second.items].map((mission) => mission.id)).size).toBe(3);

      const overview = await missionService.getOverview();
      expect(overview.schemaVersion).toBe("2.4");
      expect(overview.readiness).toMatchObject({ status: "degraded", score: 65 });
      expect(overview.summary.activeMissions).toBe(3);
      expect(overview.missions).toHaveLength(3);
      expect(overview.system.database).toBe("healthy");
      expect(overview.system.providers).toBe("healthy");
      expect(overview.agents).toEqual([{
        id: "agent-recon",
        name: "Recon specialist",
        status: "available",
      }]);
    } finally {
      database.close();
    }
  });
});
