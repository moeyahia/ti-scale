import { describe, expect, test } from "bun:test";
import { BrainContextService } from "../../brain-runtime";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
  RunMutationAuthorityGuard,
} from "../../control-plane";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import {
  AutonomousBranchService,
  IdempotencyConflictError,
  MissionRepository,
  MissionService,
  OverviewRepository,
  ReadinessService,
  type AutonomousMissionRequest,
  type ReadinessCheckProvider,
} from "../index";

const NOW = "2026-07-15T16:00:00.000Z";
const assertMutationAuthority = () => {};

const request: AutonomousMissionRequest = {
  journey: "autonomous",
  launch: true,
  title: "Authorized branch fixture",
  objective: "Collect one bounded service inventory",
  successCriteria: ["A unique evidence-backed inventory is retained"],
  authorization: {
    engagementId: "eng-branch",
    allowedTargets: ["lab.internal"],
    prohibitedTargets: [],
    authorizationConfirmed: true,
    dataHandling: "Keep evidence local",
  },
  contract: {
    allowedActionClasses: ["reconnaissance"],
    prohibitedActionClasses: ["destructive"],
    destructivePolicy: "prohibited",
    evidenceRequirements: ["Hash retained evidence"],
    timeBudgetMinutes: 30,
    tokenBudget: 10_000,
    costBudget: 2,
    retryBudget: 1,
    replanBudget: 1,
    concurrencyLimit: 1,
    evidenceStorageBudgetBytes: 8 * 1024 * 1024,
    artifactStorageBudgetBytes: 16 * 1024 * 1024,
    notificationPolicy: "in_app_only",
    reportingFormat: "ti_scale_json",
    dataHandlingPolicy: "local_private",
    retentionPolicy: "operator_managed",
    providerPolicy: "automatic_enforcing_only",
    toolPolicy: "contract_allowlist",
    specialistAgentIds: ["agent-branch-recon"],
    memoryScopes: ["verified_lessons"],
    contextNodeIds: [],
    safeStopConditions: ["The target leaves the exact signed scope"],
    deliverables: ["Evidence-backed Ti-Scale report"],
  },
};

const readiness: ReadinessCheckProvider = {
  id: "branch-runtime",
  label: "Branch runtime",
  journeys: ["autonomous", "guided"],
  evaluate: () => ({
    id: "branch-runtime",
    label: "Branch runtime",
    journeys: ["autonomous", "guided"],
    status: "pass",
    impact: "The enforcing runtime is available.",
  }),
};

function setup() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  const attestedAt = new Date().toISOString();
  const validUntil = new Date(Date.now() + 5 * 60_000).toISOString();
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (
      'agent-branch-recon', 'reconnaissance', 'Branch Recon', 'available',
      '{"defaultProvider":"xai-grok-oauth"}',
      '{"allowedTools":["nmap"],"deniedTools":[],"approvalRequiredTools":[]}',
      '{}', '2.4', ?, ?, ?
    )
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO agent_capabilities (agent_id, capability, source, enabled, metadata_json)
    VALUES ('agent-branch-recon', 'nmap', 'live-route-attestation', 1, ?)
  `).run(JSON.stringify({ attestedAt, validUntil, providerIds: ["xai-grok-oauth"] }));
  database.prepare(`
    INSERT INTO mcp_servers (
      id, name, transport, endpoint_redacted, status, capabilities_json,
      policy_json, last_checked_at, created_at, updated_at
    ) VALUES (
      'mcp:branch-nmap', 'branch-nmap', 'stdio', 'local fixture', 'healthy', '["nmap"]',
      '{"enabled":true,"assignedAgents":["agent-branch-recon"],"startPermitted":true,"riskClass":"low"}',
      ?, ?, ?
    )
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO health_snapshots (
      id, component_type, component_id, status, metrics_json, message, captured_at
    ) VALUES (
      'health-branch-provider', 'provider', 'xai-grok-oauth', 'healthy',
      ?,
      'Authenticated enforcing provider', ?
    )
  `).run(JSON.stringify({
    authenticated: true,
    callable: true,
    attestedAt,
    expiresAt: validUntil,
    enforcesAutonomousBoundary: true,
    reportsExactTokenUsage: true,
    reportsExactCostUsage: true,
  }), attestedAt);
  const missions = new MissionService(
    new MissionRepository(database),
    new OverviewRepository(database),
    new ReadinessService([readiness]),
    new BrainContextService({
      database,
      secondBrain: new SecondBrainService(new MemoryRepository(database)),
    }),
  );
  const branches = new AutonomousBranchService(database, missions, () => new Date(NOW));
  return { database, missions, branches };
}

describe("AutonomousBranchService", () => {
  test("fences both branch mutations with a current trusted source-run lease and denies replay after authority loss", async () => {
    const { database, missions, branches } = setup();
    try {
      const initialReview = await missions.preflightAutonomous(request);
      const initial = await missions.create(
        { ...request, contractReview: initialReview.contract },
        "branch-authority-initial",
        "operator-branch",
      );
      database.prepare(`
        UPDATE runs SET status = 'completed', status_reason = 'Completed autonomously',
          ended_at = ?, updated_at = ?, version = version + 1 WHERE id = ?
      `).run(NOW, NOW, initial.run.id);
      database.prepare("UPDATE missions SET status = 'completed', updated_at = ? WHERE id = ?")
        .run(NOW, initial.mission.id);
      const context = branches.context(initial.mission.id, initial.run.id);
      const leases = new ControlPlaneLeaseService(database);
      const owner = "autonomous-branch-runtime";
      const token = "autonomous-branch-runtime-token-0000";
      leases.acquire({
        runId: initial.run.id,
        controlPlane: "ti_scale",
        leaseOwner: owner,
        leaseToken: token,
        ttlMs: 300_000,
        now: new Date(NOW),
      });
      const guard = new RunMutationAuthorityGuard(database, () => new Date(NOW));
      const assertLease = ({ runId }: { readonly runId: string }) => leases.assertMutationAuthority({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: owner,
        leaseToken: token,
        now: new Date(NOW),
      });
      const amendment = {
        ...request,
        objective: "Collect and verify the inventory under a versioned authority fence",
      } satisfies AutonomousMissionRequest;
      const preflightAuthority = guard.authorize({
        runId: initial.run.id,
        actorId: "operator-branch",
        mode: "lease",
        assertLease,
      });
      const draft = await branches.preflight(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "Verify branch preflight under the current source runtime authority",
          request: amendment,
        },
        "branch-authority-preflight",
        "operator-branch",
        preflightAuthority.assertCurrent,
      );
      const createAuthority = guard.authorize({
        runId: initial.run.id,
        actorId: "operator-branch",
        mode: "lease",
        assertLease,
      });
      const created = await branches.createBranch(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "Confirm the reviewed branch under the current source runtime authority",
          draftContractId: draft.contract.id!,
          review: { version: draft.contract.version, hash: draft.contract.hash },
        },
        "branch-authority-create",
        "operator-branch",
        createAuthority.assertCurrent,
      );
      expect(created.run.status).toBe("planning");
      leases.release({
        runId: initial.run.id,
        controlPlane: "ti_scale",
        leaseOwner: owner,
        leaseToken: token,
        now: new Date(NOW),
      });
      expect(() => guard.authorize({
        runId: initial.run.id,
        actorId: "operator-branch",
        mode: "lease",
        assertLease,
      })).toThrow(ControlPlaneLeaseError);
      expect(database.prepare("SELECT COUNT(*) AS count FROM runs WHERE mission_id = ?").get(initial.mission.id))
        .toEqual({ count: 2 });

      database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(initial.mission.id);
      expect(() => guard.authorize({
        runId: initial.run.id,
        actorId: "operator-branch",
        mode: "lease",
        assertLease,
      })).toThrow(ControlPlaneLeaseError);
      expect(() => guard.authorize({
        runId: created.run.id,
        actorId: "operator-branch",
        mode: "lease",
      })).toThrow(ControlPlaneLeaseError);
    } finally {
      database.close();
    }
  });

  test("rolls back an amendment draft when the source controller is taken over at the atomic fence", async () => {
    const { database, missions, branches } = setup();
    try {
      const review = await missions.preflightAutonomous(request);
      const initial = await missions.create(
        { ...request, contractReview: review.contract },
        "branch-takeover-initial",
        "operator-branch",
      );
      database.prepare(`
        UPDATE runs SET status = 'completed', ended_at = ?, updated_at = ?, version = version + 1
        WHERE id = ?
      `).run(NOW, NOW, initial.run.id);
      database.prepare("UPDATE missions SET status = 'completed' WHERE id = ?").run(initial.mission.id);
      const context = branches.context(initial.mission.id, initial.run.id);
      const leases = new ControlPlaneLeaseService(database);
      const owner = "branch-before-takeover";
      const token = "branch-before-takeover-token-000000";
      leases.acquire({
        runId: initial.run.id,
        controlPlane: "ti_scale",
        leaseOwner: owner,
        leaseToken: token,
        ttlMs: 300_000,
        now: new Date(NOW),
      });
      let checks = 0;
      const authority = new RunMutationAuthorityGuard(database, () => new Date(NOW)).authorize({
        runId: initial.run.id,
        actorId: "operator-branch",
        mode: "lease",
        assertLease: ({ runId }) => {
          checks += 1;
          if (checks === 3) {
            leases.release({
              runId,
              controlPlane: "ti_scale",
              leaseOwner: owner,
              leaseToken: token,
              now: new Date("2026-07-15T16:00:01.000Z"),
            });
            const takeoverOwner = "branch-after-takeover";
            const takeoverToken = "branch-after-takeover-token-0000000";
            leases.acquire({
              runId,
              controlPlane: "ti_scale",
              leaseOwner: takeoverOwner,
              leaseToken: takeoverToken,
              ttlMs: 300_000,
              now: new Date("2026-07-15T16:00:02.000Z"),
            });
            return leases.assertMutationAuthority({
              runId,
              controlPlane: "ti_scale",
              leaseOwner: takeoverOwner,
              leaseToken: takeoverToken,
              now: new Date("2026-07-15T16:00:02.000Z"),
            });
          }
          return leases.assertMutationAuthority({
            runId,
            controlPlane: "ti_scale",
            leaseOwner: owner,
            leaseToken: token,
            now: new Date(NOW),
          });
        },
      });
      await expect(branches.preflight(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "A controller takeover must roll back the pending amendment draft",
          request: { ...request, objective: "Changed only inside an authority-fenced draft" },
        },
        "branch-takeover-preflight",
        "operator-branch",
        authority.assertCurrent,
      )).rejects.toMatchObject({ code: "lease_fence_invalid" });
      expect(database.prepare("SELECT COUNT(*) AS count FROM mission_contracts").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM settings WHERE key LIKE 'idempotency.mission.autonomous_branch.%'").get())
        .toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("confirms a versioned amendment into one separate run without mutating the source run", async () => {
    const { database, missions, branches } = setup();
    try {
      const initialReview = await missions.preflightAutonomous(request);
      const initial = await missions.create(
        { ...request, contractReview: initialReview.contract },
        "branch-initial-create",
        "operator-branch",
      );
      database.prepare(`
        UPDATE runs SET status = 'completed', status_reason = 'Completed autonomously',
          ended_at = ?, updated_at = ?, version = version + 1 WHERE id = ?
      `).run(NOW, NOW, initial.run.id);
      database.prepare("UPDATE missions SET status = 'completed', updated_at = ? WHERE id = ?")
        .run(NOW, initial.mission.id);

      const context = branches.context(initial.mission.id, initial.run.id);
      expect(context.sourceRun).toMatchObject({ status: "completed", safeToBranch: true });
      expect(context.contract).toMatchObject({ version: 1, state: "confirmed" });

      const amendment: AutonomousMissionRequest = {
        ...request,
        objective: "Collect and independently verify one bounded service inventory",
        successCriteria: [
          ...request.successCriteria,
          "The follow-up contains a fresh immutable evidence delta",
        ],
        contract: {
          ...request.contract,
          timeBudgetMinutes: 45,
          deliverables: [...request.contract.deliverables, "Versioned comparison summary"],
        },
      };
      const draft = await branches.preflight(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "Add an independently verified evidence delta and comparison deliverable",
          request: amendment,
        },
        "branch-amendment-preflight",
        "operator-branch",
        assertMutationAuthority,
      );
      expect(draft.contract).toMatchObject({ version: 2, state: "draft" });
      expect(draft.preflight.readiness.status).toBe("ready");
      expect(database.prepare("SELECT state FROM mission_contracts WHERE id = ?").get(draft.contract.id!))
        .toEqual({ state: "draft" });
      expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(initial.run.id))
        .toEqual({ status: "completed" });

      const created = await branches.createBranch(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "Add an independently verified evidence delta and comparison deliverable",
          draftContractId: draft.contract.id!,
          review: { version: draft.contract.version, hash: draft.contract.hash },
        },
        "branch-amendment-create",
        "operator-branch",
        assertMutationAuthority,
      );
      expect(created).toMatchObject({
        sourceRunId: initial.run.id,
        branchMode: "contract_amendment",
        run: { journey: "autonomous", status: "planning", contractId: draft.contract.id },
        contract: { version: 2, state: "confirmed", hash: draft.contract.hash },
      });
      expect(database.prepare("SELECT status, contract_id FROM runs WHERE id = ?").get(initial.run.id))
        .toEqual({ status: "completed", contract_id: context.contract.id });
      expect(database.prepare("SELECT state FROM mission_contracts WHERE id = ?").get(context.contract.id))
        .toEqual({ state: "superseded" });
      expect(database.prepare("SELECT state FROM mission_contracts WHERE id = ?").get(draft.contract.id!))
        .toEqual({ state: "confirmed" });
      expect(database.prepare("SELECT objective FROM missions WHERE id = ?").get(initial.mission.id))
        .toEqual({ objective: amendment.objective });
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_branches WHERE run_id = ?").get(created.run.id))
        .toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE run_id = ? AND event_type = 'run.autonomous_branch_created'
      `).get(created.run.id)).toEqual({ count: 1 });

      const replay = await branches.createBranch(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "Add an independently verified evidence delta and comparison deliverable",
          draftContractId: draft.contract.id!,
          review: { version: draft.contract.version, hash: draft.contract.hash },
        },
        "branch-amendment-create",
        "operator-branch",
        assertMutationAuthority,
      );
      expect(replay.run.id).toBe(created.run.id);
      expect(database.prepare("SELECT COUNT(*) AS count FROM runs WHERE mission_id = ?").get(initial.mission.id))
        .toEqual({ count: 2 });

      await expect(branches.createBranch(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "A materially different request using the same idempotency key",
          draftContractId: draft.contract.id!,
          review: { version: draft.contract.version, hash: draft.contract.hash },
        },
        "branch-amendment-create",
        "operator-branch",
        assertMutationAuthority,
      )).rejects.toBeInstanceOf(IdempotencyConflictError);
    } finally {
      database.close();
    }
  });

  test("refuses to branch a running source and persists no draft or successor run", async () => {
    const { database, missions, branches } = setup();
    try {
      const review = await missions.preflightAutonomous(request);
      const initial = await missions.create(
        { ...request, contractReview: review.contract },
        "branch-running-create",
        "operator-branch",
      );
      const context = branches.context(initial.mission.id, initial.run.id);
      expect(context.sourceRun.safeToBranch).toBe(false);
      const result = await branches.preflight(
        initial.mission.id,
        {
          sourceRunId: initial.run.id,
          sourceRunVersion: context.sourceRun.version,
          mode: "contract_amendment",
          reason: "This must not amend a running mission in place",
          request: { ...request, objective: "Changed while running" },
        },
        "branch-running-preflight",
        "operator-branch",
        assertMutationAuthority,
      );
      expect(result).toMatchObject({ safeToBranch: false, contract: { state: "unpersisted" } });
      expect(database.prepare("SELECT COUNT(*) AS count FROM mission_contracts").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });
});
