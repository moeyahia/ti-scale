import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { EventRepository } from "../../events";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
  RunMutationAuthorityGuard,
} from "../../control-plane";
import {
  MissionApiError,
  MissionPortfolioService,
  MissionRepository,
  type Journey,
  type MissionPortfolioFilterState,
} from "../index";

const TIMES = {
  old: "2026-07-13T10:00:00.000Z",
  middle: "2026-07-14T10:00:00.000Z",
  recent: "2026-07-15T10:00:00.000Z",
};

function insertAgent(database: SqliteDatabase): void {
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES ('agent-recon', 'recon', 'Recon Specialist', 'busy', '{}', '{}', '{}', '2.4', ?, ?, ?)
  `).run(TIMES.recent, TIMES.old, TIMES.recent);
}

function insertMission(database: SqliteDatabase, input: {
  id: string;
  title: string;
  objective: string;
  journey: Journey;
  missionStatus: "active" | "completed";
  runStatus: "recovering" | "completed";
  engagement: string;
  target: string;
  updatedAt: string;
  risk?: string;
  owner?: boolean;
  evidence?: boolean;
  findingSeverity?: "informational" | "low" | "medium" | "high" | "critical";
  decision?: boolean;
  provider?: string;
}): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, version, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'verified', ?, '{}', '[]', '{}', '{}', 'operator-test', 1, ?, ?)
  `).run(
    input.id, input.title, input.objective, input.journey, input.missionStatus,
    input.engagement, TIMES.old, input.updatedAt,
  );
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, metadata_json, created_at
    ) VALUES (?, ?, ?, 'domain', 'allowed', ?, '{}', ?)
  `).run(`target-${input.id}`, input.id, input.target, input.target.toLowerCase(), TIMES.old);
  const runId = `run-${input.id}`;
  const planId = `plan-${input.id}`;
  const stepId = `step-${input.id}`;
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id, current_owner_id,
      progress, status_reason, next_action_summary, budget_json, budget_usage_json,
      started_at, ended_at, created_at, updated_at, version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Canonical fixture state', ?, ?, ?, ?, ?, ?, ?, 1)
  `).run(
    runId, input.id, input.journey, input.runStatus, planId, stepId,
    input.owner ? "agent-recon" : null,
    input.runStatus === "completed" ? 1 : 0.45,
    input.runStatus === "completed" ? "No next action" : "Inspect bounded recovery evidence",
    JSON.stringify({ providerTokens: 10_000, toolCalls: 20 }),
    JSON.stringify({ providerTokens: 750, toolCalls: 4 }),
    TIMES.middle,
    input.runStatus === "completed" ? input.updatedAt : null,
    TIMES.middle,
    input.updatedAt,
  );
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Bounded plan', 'Fixture rationale', ?, 'system', ?, ?)
  `).run(planId, runId, `hash-${input.id}`, TIMES.middle, TIMES.middle);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'reconnaissance', 'Inspect target', 'Collect bounded evidence', ?,
      '[]', '[]', 'reconnaissance', ?, ?, ?, ?, ?, ?)
  `).run(
    stepId, planId, runId,
    input.runStatus === "completed" ? "completed" : "recovering",
    input.risk ?? null,
    input.owner ? "agent-recon" : null,
    TIMES.middle,
    input.runStatus === "completed" ? input.updatedAt : null,
    TIMES.middle,
    input.updatedAt,
  );
  if (input.owner) {
    database.prepare(`
      INSERT INTO assignments (
        id, run_id, step_id, agent_id, status, started_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'agent-recon', 'blocked', ?, ?, ?)
    `).run(`assignment-${input.id}`, runId, stepId, TIMES.middle, TIMES.middle, input.updatedAt);
  }
  if (input.provider) {
    database.prepare(`
      INSERT INTO provider_turns (
        id, run_id, provider, model, status, input_tokens, output_tokens,
        latency_ms, started_at, ended_at
      ) VALUES (?, ?, ?, 'expert', 'completed', 100, 50, 120, ?, ?)
    `).run(`provider-${input.id}`, runId, input.provider, TIMES.middle, input.updatedAt);
  }
  if (input.decision) {
    database.prepare(`
      INSERT INTO guided_decisions (
        id, mission_id, run_id, step_id, requested_action_fingerprint,
        requested_parameters_json, rationale, risk_class, reversibility,
        status, expires_at, created_at
      ) VALUES (?, ?, ?, ?, 'fingerprint', '{}', 'Bounded recovery choice', 'high',
        'reversible', 'pending', '2026-07-20T00:00:00.000Z', ?)
    `).run(`decision-${input.id}`, input.id, runId, stepId, input.updatedAt);
  }
  if (input.evidence) {
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity, verification_state,
        summary, extracted_text, created_by, created_at
      ) VALUES (?, ?, ?, ?, 'fixture', ?, ?, 'scan', ?, '{}', .9, 'private',
        'verified', 'SENSITIVE EVIDENCE SUMMARY', 'SENSITIVE RAW BODY', 'agent-recon', ?)
    `).run(`evidence-${input.id}`, input.id, runId, stepId, input.updatedAt, input.target, "a".repeat(64), input.updatedAt);
  }
  if (input.findingSeverity) {
    database.prepare(`
      INSERT INTO findings (
        id, mission_id, run_id, title, severity, confidence, affected_scope,
        description, impact, remediation, review_status, created_at, updated_at
      ) VALUES (?, ?, ?, 'Fixture finding', ?, .9, 'fixture', 'description', 'impact',
        'remediation', 'verified', ?, ?)
    `).run(`finding-${input.id}`, input.id, runId, input.findingSeverity, input.updatedAt, input.updatedAt);
  }
  new EventRepository(database).append({
    missionId: input.id,
    runId,
    journey: input.journey,
    eventType: input.runStatus === "completed" ? "run.completed" : "run.recovery_started",
    occurredAt: input.updatedAt,
    actorType: "system",
    actorId: "fixture",
    summary: input.runStatus === "completed"
      ? "Mission completed with canonical evidence"
      : "Recovery started after a bounded failure",
    payload: {},
  });
}

function fixture() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  insertAgent(database);
  insertMission(database, {
    id: "mission-guided-recovery",
    title: "Guided recovery",
    objective: "SENSITIVE OBJECTIVE A",
    journey: "guided",
    missionStatus: "active",
    runStatus: "recovering",
    engagement: "engagement-red",
    target: "recover.internal",
    updatedAt: TIMES.recent,
    risk: "high",
    owner: true,
    evidence: true,
    findingSeverity: "critical",
    decision: true,
    provider: "grok-acp",
  });
  insertMission(database, {
    id: "mission-auto-terminal",
    title: `${"T".repeat(130)} terminal`,
    objective: "SENSITIVE OBJECTIVE B",
    journey: "autonomous",
    missionStatus: "completed",
    runStatus: "completed",
    engagement: "engagement-blue",
    target: "terminal.internal",
    updatedAt: TIMES.middle,
    risk: "low",
    evidence: true,
    findingSeverity: "low",
    provider: "codex-oauth",
  });
  insertMission(database, {
    id: "mission-guided-terminal",
    title: "Older Guided mission",
    objective: "SENSITIVE OBJECTIVE C",
    journey: "guided",
    missionStatus: "completed",
    runStatus: "completed",
    engagement: "engagement-green",
    target: "older.internal",
    updatedAt: TIMES.old,
  });
  return database;
}

const savedState: MissionPortfolioFilterState = {
  query: "recovery",
  journey: "guided",
  status: "recovering",
  engagement: "engagement-red",
  target: "recover.internal",
  agent: "agent-recon",
  provider: "grok-acp",
  updatedFrom: "2026-07-15",
  updatedTo: "2026-07-15",
  risk: "high",
  evidence: "present",
  findingSeverity: "critical",
  decisionState: "pending",
  recoveryState: "recovering",
  view: "board",
};

function archiveAuthorities(portfolio: MissionPortfolioService, missionIds: readonly string[]) {
  return portfolio.archiveAuthorityScopes(missionIds).map((scope) => ({
    ...scope,
    assertCurrent: () => {},
  }));
}

describe("Mission Portfolio canonical service", () => {
  test("bulk archive fails atomically for missing, imported, taken-over, and replay-lost authorities", () => {
    const missing = fixture();
    try {
      const portfolio = new MissionPortfolioService(missing);
      expect(() => portfolio.archive({
        actorId: "operator-a",
        idempotencyKey: "archive-missing-authority",
        missionIds: ["mission-auto-terminal"],
        mutationAuthorities: [],
      })).toThrow(MissionApiError);
      expect(missing.prepare("SELECT status FROM missions WHERE id = 'mission-auto-terminal'").get())
        .toEqual({ status: "completed" });

      missing.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = 'mission-guided-recovery'").run();
      const guard = new RunMutationAuthorityGuard(missing, () => new Date(TIMES.recent));
      expect(() => guard.authorize({
        runId: "run-mission-guided-recovery",
        actorId: "operator-a",
        mode: "lease",
        assertLease: () => undefined,
      })).toThrow(ControlPlaneLeaseError);
      expect(missing.prepare("SELECT status FROM missions WHERE id = 'mission-auto-terminal'").get())
        .toEqual({ status: "completed" });
    } finally {
      missing.close();
    }

    const takeover = fixture();
    try {
      const portfolio = new MissionPortfolioService(takeover);
      const leases = new ControlPlaneLeaseService(takeover);
      const runId = "run-mission-auto-terminal";
      const owner = "portfolio-before-takeover";
      const token = "portfolio-before-takeover-token-0000";
      leases.acquire({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: owner,
        leaseToken: token,
        ttlMs: 300_000,
        now: new Date(TIMES.recent),
      });
      let checks = 0;
      const authority = new RunMutationAuthorityGuard(takeover, () => new Date(TIMES.recent)).authorize({
        runId,
        actorId: "operator-a",
        mode: "lease",
        assertLease: ({ runId: requestedRunId }) => {
          checks += 1;
          if (checks === 2) {
            leases.release({
              runId: requestedRunId,
              controlPlane: "ti_scale",
              leaseOwner: owner,
              leaseToken: token,
              now: new Date("2026-07-15T10:00:01.000Z"),
            });
            const nextOwner = "portfolio-after-takeover";
            const nextToken = "portfolio-after-takeover-token-00000";
            leases.acquire({
              runId: requestedRunId,
              controlPlane: "ti_scale",
              leaseOwner: nextOwner,
              leaseToken: nextToken,
              ttlMs: 300_000,
              now: new Date("2026-07-15T10:00:02.000Z"),
            });
            return leases.assertMutationAuthority({
              runId: requestedRunId,
              controlPlane: "ti_scale",
              leaseOwner: nextOwner,
              leaseToken: nextToken,
              now: new Date("2026-07-15T10:00:02.000Z"),
            });
          }
          return leases.assertMutationAuthority({
            runId: requestedRunId,
            controlPlane: "ti_scale",
            leaseOwner: owner,
            leaseToken: token,
            now: new Date(TIMES.recent),
          });
        },
      });
      expect(() => portfolio.archive({
        actorId: "operator-a",
        idempotencyKey: "archive-controller-takeover",
        missionIds: ["mission-auto-terminal"],
        mutationAuthorities: [{
          missionId: "mission-auto-terminal",
          runId,
          assertCurrent: authority.assertCurrent,
        }],
      })).toThrow(ControlPlaneLeaseError);
      expect(takeover.prepare("SELECT status FROM missions WHERE id = 'mission-auto-terminal'").get())
        .toEqual({ status: "completed" });
      expect(takeover.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE action = 'mission.archived'").get())
        .toEqual({ count: 0 });
    } finally {
      takeover.close();
    }

    const replay = fixture();
    try {
      const portfolio = new MissionPortfolioService(replay);
      const leases = new ControlPlaneLeaseService(replay);
      const runId = "run-mission-auto-terminal";
      const owner = "portfolio-replay-runtime";
      const token = "portfolio-replay-runtime-token-000000";
      leases.acquire({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: owner,
        leaseToken: token,
        ttlMs: 300_000,
        now: new Date(TIMES.recent),
      });
      const guard = new RunMutationAuthorityGuard(replay, () => new Date(TIMES.recent));
      const resolver = ({ runId: requestedRunId }: { readonly runId: string }) =>
        leases.assertMutationAuthority({
          runId: requestedRunId,
          controlPlane: "ti_scale",
          leaseOwner: owner,
          leaseToken: token,
          now: new Date(TIMES.recent),
        });
      const authority = guard.authorize({ runId, actorId: "operator-a", mode: "lease", assertLease: resolver });
      const input = {
        actorId: "operator-a",
        idempotencyKey: "archive-authorized-replay",
        missionIds: ["mission-auto-terminal"],
        mutationAuthorities: [{ missionId: "mission-auto-terminal", runId, assertCurrent: authority.assertCurrent }],
      } as const;
      expect(portfolio.archive(input).archivedCount).toBe(1);
      leases.release({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: owner,
        leaseToken: token,
        now: new Date(TIMES.recent),
      });
      expect(() => guard.authorize({
        runId,
        actorId: "operator-a",
        mode: "lease",
        assertLease: resolver,
      })).toThrow(ControlPlaneLeaseError);
      expect(replay.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE action = 'mission.archived'").get())
        .toEqual({ count: 1 });
    } finally {
      replay.close();
    }
  });

  test("filters canonical mission relationships and binds signed cursors to the exact filter set", () => {
    const database = fixture();
    try {
      const repository = new MissionRepository(database);
      const filtered = repository.list({
        limit: 10,
        journey: "guided",
        status: "recovering",
        query: "bounded recovery",
        engagement: "engagement-red",
        target: "recover.internal",
        agent: "agent-recon",
        provider: "grok-acp",
        updatedFrom: "2026-07-15T00:00:00.000Z",
        updatedTo: "2026-07-15T23:59:59.999Z",
        risk: "high",
        evidence: "present",
        findingSeverity: "critical",
        decisionState: "pending",
        recoveryState: "recovering",
      });
      expect(filtered.items).toHaveLength(1);
      expect(filtered.items[0]).toMatchObject({
        id: "mission-guided-recovery",
        engagementId: "engagement-red",
        activeRunId: "run-mission-guided-recovery",
        currentPhase: "reconnaissance",
        currentOwner: { id: "agent-recon", name: "Recon Specialist" },
        provider: "grok-acp",
        risk: "high",
        evidenceCount: 1,
        highestFindingSeverity: "critical",
        decisionState: "pending",
        recoveryState: "recovering",
        budget: { limits: { providerTokens: 10_000, toolCalls: 20 }, usage: { providerTokens: 750, toolCalls: 4 } },
      });
      expect(filtered.items[0]?.lastMeaningfulEvent?.summary).toContain("Recovery started");
      expect(filtered.items[0]?.scope.allowedTargets).toEqual(["recover.internal"]);
      expect(filtered.items[0]?.team).toEqual([{ id: "agent-recon", name: "Recon Specialist" }]);

      const base = { journey: "guided" as const, status: "recovering" };
      for (const mismatch of [
        { engagement: "engagement-blue" },
        { target: "missing.internal" },
        { agent: "agent-other" },
        { provider: "provider-other" },
        { updatedFrom: "2026-07-16T00:00:00.000Z" },
        { updatedTo: "2026-07-14T23:59:59.999Z" },
        { risk: "low" },
        { evidence: "none" as const },
        { findingSeverity: "low" },
        { decisionState: "rejected" },
        { recoveryState: "blocked" as const },
      ]) {
        expect(repository.list({ ...base, ...mismatch }).items).toEqual([]);
      }

      const first = repository.list({ limit: 1, journey: "guided" });
      expect(first.nextCursor).toBeString();
      expect(() => repository.list({ limit: 1, journey: "guided", status: "completed", cursor: first.nextCursor! }))
        .toThrow(RangeError);
      const tampered = `${first.nextCursor!.slice(0, -1)}${first.nextCursor!.endsWith("A") ? "B" : "A"}`;
      expect(() => repository.list({ limit: 1, journey: "guided", cursor: tampered })).toThrow(RangeError);
      expect(repository.list({ limit: 1, journey: "guided", cursor: first.nextCursor! }).items[0]?.id)
        .toBe("mission-guided-terminal");
    } finally {
      database.close();
    }
  });

  test("reports a paused older run independently from the newest completed attempt", () => {
    const database = fixture();
    try {
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          created_at, updated_at, version
        ) VALUES (
          'run-auto-paused-source', 'mission-auto-terminal', 'autonomous',
          'blocked', 0.5, 'Paused by operator: branch source retained', ?, ?, 1
        )
      `).run(TIMES.old, TIMES.recent);
      const [mission] = new MissionRepository(database).list({
        limit: 10,
        query: "terminal",
      }).items;
      expect(mission).toMatchObject({
        id: "mission-auto-terminal",
        runId: "run-mission-auto-terminal",
        status: "completed",
        activeRunId: "run-auto-paused-source",
      });
    } finally {
      database.close();
    }
  });

  test("synchronizes actor-scoped saved views with optimistic versioning and idempotency", () => {
    const database = fixture();
    try {
      const portfolio = new MissionPortfolioService(database);
      const saved = portfolio.saveView({
        actorId: "operator-a",
        idempotencyKey: "saved-view-request-a",
        expectedVersion: 0,
        name: "Guided recovery board",
        state: savedState,
      });
      expect(saved.version).toBe(1);
      expect(saved.items[0]).toMatchObject({ name: "Guided recovery board", state: savedState });
      expect(portfolio.saveView({
        actorId: "operator-a",
        idempotencyKey: "saved-view-request-a",
        expectedVersion: 0,
        name: "Guided recovery board",
        state: savedState,
      })).toEqual(saved);
      expect(portfolio.listSavedViews("operator-b")).toMatchObject({ version: 0, items: [] });
      expect(() => portfolio.saveView({
        actorId: "operator-a",
        idempotencyKey: "saved-view-request-b",
        expectedVersion: 0,
        name: "Stale view",
        state: savedState,
      })).toThrow(MissionApiError);
      let collection = saved;
      for (let index = 2; index <= 12; index += 1) {
        collection = portfolio.saveView({
          actorId: "operator-a",
          idempotencyKey: `saved-view-request-${index}`,
          expectedVersion: collection.version,
          name: `Bounded view ${index}`,
          state: savedState,
        });
      }
      expect(collection.items).toHaveLength(12);
      expect(() => portfolio.saveView({
        actorId: "operator-a",
        idempotencyKey: "saved-view-request-over-limit",
        expectedVersion: collection.version,
        name: "Thirteenth view",
        state: savedState,
      })).toThrow(MissionApiError);
      const deleted = portfolio.deleteView({
        actorId: "operator-a",
        idempotencyKey: "delete-view-request-a",
        expectedVersion: collection.version,
        viewId: saved.items[0]!.id,
      });
      expect(deleted).toMatchObject({ version: 13 });
      expect(deleted.items).toHaveLength(11);
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action IN ('mission.saved_view.upserted', 'mission.saved_view.deleted')
      `).get() as { count: number }).count).toBe(13);
    } finally {
      database.close();
    }
  });

  test("archives only durably terminal work and exports bounded redacted metadata with exact audit", () => {
    const database = fixture();
    try {
      const portfolio = new MissionPortfolioService(database);
      const selection = ["mission-auto-terminal", "mission-guided-recovery"];
      expect(() => portfolio.exportMetadata({
        actorId: "operator-a",
        idempotencyKey: "bulk-export-duplicate",
        missionIds: ["mission-auto-terminal", "mission-auto-terminal"],
      })).toThrow(MissionApiError);
      expect(() => portfolio.archive({
        actorId: "operator-a",
        idempotencyKey: "bulk-archive-over-limit",
        missionIds: Array.from({ length: 51 }, (_, index) => `mission-${index}`),
        mutationAuthorities: [],
      })).toThrow(MissionApiError);
      const archived = portfolio.archive({
        actorId: "operator-a",
        idempotencyKey: "bulk-archive-request-a",
        missionIds: selection,
        mutationAuthorities: archiveAuthorities(portfolio, selection),
      });
      expect(archived.outcomes).toEqual([
        { missionId: "mission-auto-terminal", status: "archived", reason: "Durably terminal mission archived." },
        { missionId: "mission-guided-recovery", status: "ineligible", reason: "Mission or related work is not durably terminal." },
      ]);
      expect(database.prepare("SELECT status FROM missions WHERE id = 'mission-auto-terminal'").get()).toEqual({ status: "archived" });
      expect(database.prepare("SELECT status FROM missions WHERE id = 'mission-guided-recovery'").get()).toEqual({ status: "active" });
      expect(portfolio.archive({
        actorId: "operator-a",
        idempotencyKey: "bulk-archive-request-a",
        missionIds: selection,
        mutationAuthorities: archiveAuthorities(portfolio, selection),
      })).toEqual(archived);
      const archiveAudit = database.prepare(`
        SELECT details_json FROM audit_records WHERE action = 'mission.bulk_archive_completed'
      `).get() as { details_json: string };
      expect(JSON.parse(archiveAudit.details_json)).toMatchObject({
        missionIds: selection,
        outcomes: [{ status: "archived" }, { status: "ineligible" }],
      });

      const exported = portfolio.exportMetadata({
        actorId: "operator-a",
        idempotencyKey: "bulk-export-request-a",
        missionIds: selection,
      });
      expect(exported.records).toHaveLength(2);
      expect(exported.records[0]).toMatchObject({
        missionId: "mission-auto-terminal",
        titleTruncated: true,
        engagement: { present: true },
        scope: { allowedTargetCount: 1, prohibitedTargetCount: 0 },
        evidenceCount: 1,
      });
      expect(exported.policy).toEqual({
        maxBatch: 50,
        evidenceBlobsIncluded: false,
        confidentialPayloadsIncluded: false,
        titlePreviewLimit: 120,
      });
      expect(exported.exportSha256).toMatch(/^[a-f0-9]{64}$/u);
      const serialized = JSON.stringify(exported);
      expect(serialized).not.toContain("SENSITIVE OBJECTIVE");
      expect(serialized).not.toContain("SENSITIVE EVIDENCE");
      expect(serialized).not.toContain("SENSITIVE RAW BODY");
      expect(serialized).not.toContain("terminal.internal");
      expect(serialized).not.toContain("engagement-blue");
      const audit = database.prepare(`
        SELECT details_json FROM audit_records WHERE action = 'mission.bulk_metadata_exported'
      `).get() as { details_json: string };
      expect(JSON.parse(audit.details_json)).toMatchObject({
        missionIds: selection,
        exportSha256: exported.exportSha256,
        evidenceBlobsIncluded: false,
      });
    } finally {
      database.close();
    }
  });
});
