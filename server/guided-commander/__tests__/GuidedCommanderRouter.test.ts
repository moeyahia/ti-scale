import { createHash } from "node:crypto";
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
  type ControlPlaneLease,
} from "../../control-plane";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import { canonicalJson } from "../../missions/canonical";
import { GuidedCommanderRepository } from "../GuidedCommanderRepository";
import { createGuidedCommanderRouter } from "../GuidedCommanderRouter";
import { createGuidedMemoryCandidateRouter } from "../GuidedMemoryCandidateRouter";
import { GuidedCommanderService } from "../GuidedCommanderService";
import type {
  GuidedCommanderPort,
  GuidedCommanderPortInput,
  GuidedCommanderPortResponse,
} from "../types";

const servers: Server[] = [];
const FINGERPRINT = "a".repeat(64);
const AUTHORITY_NOW = "2026-07-15T10:00:00.000Z";
const CONTROL_LEASE_OWNER = "guided-runtime-test";
const CONTROL_LEASE_TOKEN = "guided-runtime-test-token-00000001";
const TAKEOVER_LEASE_OWNER = "guided-runtime-takeover";
const TAKEOVER_LEASE_TOKEN = "guided-runtime-takeover-token-0001";
type LeaseMode = "valid" | "missing" | "wrong_token" | "wrong_fence" | "takeover";
interface AuthorityState { mode: LeaseMode }
const IDS = {
  mission: "mission-guided-commander",
  run: "run-guided-commander",
  plan: "plan-guided-commander",
  step: "step-guided-commander",
  assignment: "assignment-guided-commander",
  decision: "decision-guided-commander",
  agent: "agent-guided-commander",
  conversation: "conversation-guided-commander",
  initialMessage: "message-guided-initial",
};

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

class PlanningOnlyPort implements GuidedCommanderPort {
  readonly kind = "planning_only" as const;
  readonly supportsToolExecution = false as const;
  readonly providerId = "guided-test-provider";
  readonly model = "guided-test-model";
  readonly calls: GuidedCommanderPortInput[] = [];
  response?: (input: GuidedCommanderPortInput) => GuidedCommanderPortResponse;

  async respond(input: GuidedCommanderPortInput, signal: AbortSignal): Promise<GuidedCommanderPortResponse> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    this.calls.push(input);
    if (this.response) return this.response(input);
    const remembered = input.brainContext.items[0];
    return {
      body: input.action === "interpret_result"
        ? "The submitted output adds evidence for the current step, but the operator must still decide what to run next."
        : "This step gathers bounded evidence for the current objective. No command was executed and the represented action is unchanged.",
      summary: "Explained the current represented Guided step",
      confidence: 0.86,
      observations: ["The mission remains paused at the exact represented step"],
      recommendedNextStep: "Review the existing action card and choose one deliberate control.",
      contextUse: remembered ? [{
        nodeId: remembered.nodeId,
        used: true,
        relevanceReason: "Confirmed preference applies to Guided explanations",
        influenceSummary: "Kept the explanation concise and evidence-led",
      }] : [],
    };
  }
}

class DeferredPlanningOnlyPort implements GuidedCommanderPort {
  readonly kind = "planning_only" as const;
  readonly supportsToolExecution = false as const;
  readonly providerId = "guided-deferred-test-provider";
  readonly model = "guided-deferred-test-model";
  readonly calls: GuidedCommanderPortInput[] = [];
  readonly started: Promise<void>;
  readonly #pending: Array<(response: GuidedCommanderPortResponse) => void> = [];
  #resolveStarted!: () => void;

  constructor() {
    this.started = new Promise<void>((resolve) => {
      this.#resolveStarted = resolve;
    });
  }

  respond(input: GuidedCommanderPortInput, signal: AbortSignal): Promise<GuidedCommanderPortResponse> {
    if (signal.aborted) return Promise.reject(new DOMException("Aborted", "AbortError"));
    this.calls.push(input);
    this.#resolveStarted();
    return new Promise<GuidedCommanderPortResponse>((resolve, reject) => {
      signal.addEventListener(
        "abort",
        () => reject(new DOMException("Aborted", "AbortError")),
        { once: true },
      );
      this.#pending.push(resolve);
    });
  }

  releaseAll(): void {
    const response: GuidedCommanderPortResponse = {
      body: "The submitted output is interpreted once while the exact Guided step remains operator-controlled.",
      summary: "Interpreted one coalesced Guided result",
      confidence: 0.9,
      observations: ["Concurrent retries produced no duplicate operational state"],
      recommendedNextStep: "Review the same represented action card.",
      contextUse: [],
    };
    for (const resolve of this.#pending.splice(0)) resolve(response);
  }
}

class ExpiringOwnerPort implements GuidedCommanderPort {
  readonly kind = "planning_only" as const;
  readonly supportsToolExecution = false as const;
  readonly providerId = "guided-expired-owner-test-provider";
  readonly calls: GuidedCommanderPortInput[] = [];
  readonly firstStarted: Promise<void>;
  #resolveFirstStarted!: () => void;
  #resolveFirst?: () => void;

  constructor() {
    this.firstStarted = new Promise<void>((resolve) => { this.#resolveFirstStarted = resolve; });
  }

  respond(input: GuidedCommanderPortInput): Promise<GuidedCommanderPortResponse> {
    this.calls.push(input);
    if (this.calls.length === 1) {
      this.#resolveFirstStarted();
      return new Promise<GuidedCommanderPortResponse>((resolve) => {
        this.#resolveFirst = () => resolve(this.response(
          "Expired owner returned after its reservation was replaced.",
          input.brainContext.items[0]?.nodeId,
        ));
      });
    }
    return Promise.resolve(this.response(
      "Recovered owner completed after the expired lease.",
      input.brainContext.items[0]?.nodeId,
    ));
  }

  releaseFirst(): void {
    this.#resolveFirst?.();
  }

  private response(body: string, nodeId?: string): GuidedCommanderPortResponse {
    return {
      body,
      summary: "One durable owner committed the Guided response",
      confidence: 0.9,
      observations: ["The idempotency reservation fenced the final exchange"],
      recommendedNextStep: "Review the existing exact action card.",
      contextUse: nodeId ? [{
        nodeId,
        used: true,
        relevanceReason: "Confirmed preference applies to this Guided response",
        influenceSummary: "Kept the response concise and evidence-led",
      }] : [],
    };
  }
}

function seedGuidedRuntime(database: SqliteDatabase): void {
  const now = AUTHORITY_NOW;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      scope_json, created_by, created_at, updated_at
    ) VALUES (?, 'Guided Commander mission', 'Validate lab evidence carefully', 'guided',
      'active', 'verified', 'eng-guided', ?, 'operator-test', ?, ?)
  `).run(IDS.mission, canonicalJson({ target: "lab.internal" }), now, now);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (?, 'recon', 'Recon Specialist', 'available', '1', ?, ?)
  `).run(IDS.agent, now, now);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, progress, status_reason, next_action_summary,
      created_at, updated_at
    ) VALUES (?, ?, 'guided', 'waiting_guided_decision', ?, ?, ?, 0,
      'Waiting for one exact operator decision', 'Review the represented step', ?, ?)
  `).run(IDS.run, IDS.mission, IDS.plan, IDS.step, IDS.agent, now, now);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Gather evidence in bounded steps',
      'Avoid unrepresented work', ?, 'runtime-planner', ?, ?)
  `).run(IDS.plan, IDS.run, "b".repeat(64), now, now);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'Reconnaissance', 'Inspect the approved service',
      'Determine the exposed service without changing it', 'waiting_guided_decision',
      ?, '[]', 'reconnaissance', 'low', ?, ?, ?)
  `).run(
    IDS.step,
    IDS.plan,
    IDS.run,
    canonicalJson(["A service banner is retained as evidence"]),
    IDS.agent,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'queued', ?, ?)
  `).run(IDS.assignment, IDS.run, IDS.step, IDS.agent, now, now);
  database.prepare(`
    INSERT INTO mission_constraints (
      id, mission_id, constraint_type, value_json, source, created_at
    ) VALUES ('constraint-guided-representation', ?, 'represented_action', ?, ?, ?)
  `).run(
    IDS.mission,
    canonicalJson({
      action: {
        actionType: "service_banner",
        actionClass: "reconnaissance",
        target: "lab.internal",
        arguments: { target: "lab.internal", ports: [443] },
        intentSummary: "Inspect the approved service banner",
        kind: "tool",
        idempotent: true,
        destructive: false,
      },
      explanation: "Inspect one approved service without expanding scope.",
      rationale: "A banner can identify the next evidence-led branch.",
      reversibility: "Read-only and reversible.",
      dependencies: [],
    }),
    IDS.step,
    now,
  );
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'Inspect the approved service', 'low',
      'Read-only', 'pending', '2026-07-16T10:00:00.000Z', ?)
  `).run(
    IDS.decision,
    IDS.mission,
    IDS.run,
    IDS.step,
    FINGERPRINT,
    canonicalJson({ target: "lab.internal", ports: [443] }),
    now,
  );
  database.prepare(`
    INSERT INTO conversations (
      id, mission_id, run_id, step_id, conversation_type, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'guided', ?, ?)
  `).run(IDS.conversation, IDS.mission, IDS.run, IDS.step, now, now);
  database.prepare(`
    INSERT INTO messages (
      id, conversation_id, role, body, structured_content_json, created_at
    ) VALUES (?, ?, 'assistant', 'Review the first represented Guided step.', ?, ?)
  `).run(
    IDS.initialMessage,
    IDS.conversation,
    canonicalJson({ kind: "guided_step", stepId: IDS.step, actionFingerprint: FINGERPRINT }),
    now,
  );
  new MemoryRepository(database).createNode({
    id: "memory-guided-explanation",
    nodeType: "preference",
    title: "Validate lab evidence with concise explanations",
    summary: "Use concise evidence-led explanations in Guided missions",
    body: "Explain why the evidence matters before presenting the deliberate next step.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 1,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "operator_statement",
      explanation: "Confirmed by the operator",
      sources: [{
        sourceType: "message",
        sourceId: "preference-source",
        acquiredAt: now,
      }],
    },
    authorType: "operator",
    authorId: "operator-test",
    retentionPolicy: { allowGuided: true, publicProviderDisclosure: "sanitized" },
  });
  new MemoryRepository(database).createNode({
    id: "memory-guided-local-only",
    nodeType: "lesson",
    title: "Validate lab evidence local-only detail",
    summary: "This summary is intentionally local-only",
    body: "LOCAL_ONLY_BODY_MUST_NOT_REACH_PROVIDER",
    scope: { kind: "mission", missionId: IDS.mission },
    sensitivity: "private",
    confidence: 1,
    lifecycleStatus: "verified",
    confirmationState: "not_required",
    provenance: {
      method: "derived",
      explanation: "Local-only provider-boundary fixture",
      sources: [{ sourceType: "message", sourceId: "local-only-source", acquiredAt: now }],
    },
    authorType: "system",
    authorId: "brain-test",
    retentionPolicy: { allowGuided: true, publicProviderDisclosure: "local_only" },
  });
}

async function application(): Promise<{
  database: SqliteDatabase;
  port: PlanningOnlyPort;
  url: string;
  authority: AuthorityState;
}>;
async function application<Port extends GuidedCommanderPort>(
  port: Port,
  options?: { readonly attachLeaseResolver?: boolean },
): Promise<{
  database: SqliteDatabase;
  port: Port;
  url: string;
  authority: AuthorityState;
}>;
async function application(
  port: GuidedCommanderPort = new PlanningOnlyPort(),
  options: { readonly attachLeaseResolver?: boolean } = {},
) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seedGuidedRuntime(database);
  const authority: AuthorityState = { mode: "valid" };
  const leases = new ControlPlaneLeaseService(database);
  leases.acquire({
    runId: IDS.run,
    controlPlane: "ti_scale",
    leaseOwner: CONTROL_LEASE_OWNER,
    leaseToken: CONTROL_LEASE_TOKEN,
    ttlMs: 300_000,
    now: new Date(AUTHORITY_NOW),
  });
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createGuidedCommanderRouter({
    database,
    port,
    resolveActor: () => "operator-test",
    options: { clock: () => new Date(AUTHORITY_NOW) },
    ...((options.attachLeaseResolver ?? true) ? {
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        if (authority.mode === "missing") return undefined;
        const proof = leases.assertMutationAuthority({
          runId,
          controlPlane: "ti_scale",
          leaseOwner: authority.mode === "takeover" ? TAKEOVER_LEASE_OWNER : CONTROL_LEASE_OWNER,
          leaseToken: authority.mode === "wrong_token"
            ? "wrong-guided-runtime-token-000000"
            : authority.mode === "takeover" ? TAKEOVER_LEASE_TOKEN : CONTROL_LEASE_TOKEN,
          now: new Date(AUTHORITY_NOW),
        });
        return authority.mode === "wrong_fence"
          ? { ...proof, version: proof.version + 1 } satisfies ControlPlaneLease
          : proof;
      },
    } : {}),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    port,
    authority,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  };
}

async function memoryApplication(options: { readonly attachLeaseResolver?: boolean } = {}): Promise<{
  database: SqliteDatabase;
  url: string;
  authority: AuthorityState;
}> {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seedGuidedRuntime(database);
  const authority: AuthorityState = { mode: "valid" };
  const leases = new ControlPlaneLeaseService(database);
  leases.acquire({
    runId: IDS.run,
    controlPlane: "ti_scale",
    leaseOwner: CONTROL_LEASE_OWNER,
    leaseToken: CONTROL_LEASE_TOKEN,
    ttlMs: 300_000,
    now: new Date(AUTHORITY_NOW),
  });
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createGuidedMemoryCandidateRouter({
    database,
    resolveActor: () => "operator-test",
    options: { clock: () => new Date(AUTHORITY_NOW) },
    ...((options.attachLeaseResolver ?? true) ? {
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        if (authority.mode === "missing") return undefined;
        const proof = leases.assertMutationAuthority({
          runId,
          controlPlane: "ti_scale",
          leaseOwner: authority.mode === "takeover" ? TAKEOVER_LEASE_OWNER : CONTROL_LEASE_OWNER,
          leaseToken: authority.mode === "wrong_token"
            ? "wrong-guided-memory-token-00000000"
            : authority.mode === "takeover" ? TAKEOVER_LEASE_TOKEN : CONTROL_LEASE_TOKEN,
          now: new Date(AUTHORITY_NOW),
        });
        return authority.mode === "wrong_fence"
          ? { ...proof, version: proof.version + 1 } satisfies ControlPlaneLease
          : proof;
      },
    } : {}),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    authority,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  };
}

function actionBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    runId: IDS.run,
    stepId: IDS.step,
    expectedFingerprint: FINGERPRINT,
    ...extra,
  };
}

function mutation(key: string, body: unknown): RequestInit {
  return {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": key,
    },
    body: JSON.stringify(body),
  };
}

async function responseJson(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

describe("Guided Commander durable HTTP boundary", () => {
  test("fails closed on every provider and memory mutation when no trusted run-lease resolver is mounted", async () => {
    const port = new PlanningOnlyPort();
    const provider = await application(port, { attachLeaseResolver: false });
    const memory = await memoryApplication({ attachLeaseResolver: false });
    try {
      const providerRequests: Array<{ readonly action: string; readonly body: Record<string, unknown> }> = [
        { action: "explain-more", body: actionBody() },
        { action: "show-next-step", body: actionBody() },
        { action: "use-another-approach", body: actionBody({ note: "Compare one bounded alternative" }) },
        {
          action: "interpret-result",
          body: actionBody({
            result: {
              source: "paste",
              mediaType: "text/plain",
              byteSize: 18,
              text: "443/tcp open https",
            },
          }),
        },
      ];
      for (const [index, request] of providerRequests.entries()) {
        const response = await fetch(
          `${provider.url}/api/v2/guided/${IDS.mission}/commander/${request.action}`,
          mutation(`guided-no-runtime-authority-${index}`, request.body),
        );
        expect(response.status).toBe(409);
        expect(await response.json()).toMatchObject({
          error: { code: "control_plane_lease_missing", retryable: false },
        });
      }
      expect(port.calls).toHaveLength(0);
      expect(provider.database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
      expect(provider.database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get()).toEqual({ count: 0 });
      expect(provider.database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get()).toEqual({ count: 0 });
      expect(provider.database.prepare(`
        SELECT COUNT(*) AS count FROM settings
        WHERE key LIKE 'idempotency.guided-commander.%'
      `).get()).toEqual({ count: 0 });

      const remember = await fetch(
        `${memory.url}/api/v2/guided/${IDS.mission}/commander/remember`,
        mutation("guided-memory-no-runtime-authority", actionBody({
          sourceMessageId: IDS.initialMessage,
          nodeType: "preference",
          title: "Must not be retained without runtime authority",
          summary: "This candidate must never be created",
          scope: "global",
          sensitivity: "private",
        })),
      );
      const suppress = await fetch(
        `${memory.url}/api/v2/guided/${IDS.mission}/commander/do-not-remember`,
        mutation("guided-suppression-no-runtime-authority", actionBody({
          candidateId: "candidate-not-authorized",
          reason: "This request has no runtime authority",
        })),
      );
      for (const response of [remember, suppress]) {
        expect(response.status).toBe(409);
        expect(await response.json()).toMatchObject({
          error: { code: "control_plane_lease_missing", retryable: false },
        });
      }
      expect(memory.database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get())
        .toEqual({ count: 0 });
      expect(memory.database.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get())
        .toEqual({ count: 0 });
    } finally {
      provider.database.close();
      memory.database.close();
    }
  });

  test("requires V2 ownership and a current server-held lease before provider replay or scope resolution", async () => {
    const { database, port, authority, url } = await application();
    const endpoint = `${url}/api/v2/guided/${IDS.mission}/commander/explain-more`;
    try {
      database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(IDS.mission);
      const legacyMission = await fetch(endpoint, mutation("guided-legacy-mission", actionBody()));
      expect(legacyMission.status).toBe(409);
      expect(await legacyMission.json()).toMatchObject({ error: { code: "control_plane_mismatch" } });
      database.prepare("UPDATE missions SET control_plane = 'ti_scale' WHERE id = ?").run(IDS.mission);

      database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(IDS.run);
      const legacyRun = await fetch(endpoint, mutation("guided-legacy-run", actionBody()));
      expect(legacyRun.status).toBe(409);
      expect(await legacyRun.json()).toMatchObject({ error: { code: "control_plane_mismatch" } });
      database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = ?").run(IDS.run);

      authority.mode = "wrong_token";
      const wrongToken = await fetch(endpoint, mutation("guided-wrong-token", actionBody()));
      expect(wrongToken.status).toBe(409);
      expect(await wrongToken.json()).toMatchObject({
        error: { code: "control_plane_lease_authority_invalid" },
      });

      authority.mode = "wrong_fence";
      const wrongFence = await fetch(endpoint, mutation("guided-wrong-fence", actionBody()));
      expect(wrongFence.status).toBe(409);
      expect(await wrongFence.json()).toMatchObject({
        error: { code: "control_plane_lease_fence_invalid" },
      });

      authority.mode = "valid";
      database.prepare("UPDATE control_plane_leases SET expires_at = ? WHERE run_id = ?")
        .run("2026-07-15T09:59:59.000Z", IDS.run);
      const expired = await fetch(endpoint, mutation("guided-expired-lease", actionBody()));
      expect(expired.status).toBe(409);
      expect(await expired.json()).toMatchObject({ error: { code: "control_plane_lease_expired" } });
      database.prepare("UPDATE control_plane_leases SET expires_at = ? WHERE run_id = ?")
        .run("2026-07-15T10:05:00.000Z", IDS.run);

      const wrongMission = await fetch(
        `${url}/api/v2/guided/mission-other/commander/explain-more`,
        mutation("guided-wrong-mission-scope", actionBody()),
      );
      expect(wrongMission.status).toBe(404);
      expect(await wrongMission.json()).toMatchObject({ error: { code: "guided_scope_not_found" } });

      const request = mutation("guided-replay-authority", actionBody());
      const valid = await fetch(endpoint, request);
      expect(valid.status).toBe(200);
      expect(port.calls).toHaveLength(1);

      authority.mode = "missing";
      const replayWithoutAuthority = await fetch(endpoint, request);
      expect(replayWithoutAuthority.status).toBe(409);
      expect(await replayWithoutAuthority.json()).toMatchObject({
        error: { code: "control_plane_lease_missing" },
      });
      expect(port.calls).toHaveLength(1);
      expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 3 });
    } finally {
      database.close();
    }
  });

  test("refreshes a healthy heartbeat proof before committing a long-running provider response", async () => {
    const port = new DeferredPlanningOnlyPort();
    const { database, url } = await application(port);
    try {
      const pending = fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/explain-more`,
        mutation("guided-heartbeat-in-flight", actionBody()),
      );
      await port.started;
      expect(port.calls).toHaveLength(1);
      new ControlPlaneLeaseService(database).heartbeat({
        runId: IDS.run,
        controlPlane: "ti_scale",
        leaseOwner: CONTROL_LEASE_OWNER,
        leaseToken: CONTROL_LEASE_TOKEN,
        ttlMs: 300_000,
        now: new Date("2026-07-15T10:01:00.000Z"),
      });
      port.releaseAll();

      const response = await pending;
      expect(response.status).toBe(200);
      expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 3 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE event_type = 'guided.commander.explain_more'
      `).get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT status, error_category FROM provider_turns").get())
        .toEqual({ status: "completed", error_category: null });
    } finally {
      port.releaseAll();
      database.close();
    }
  });

  test("fences an interpreted-result completion after controller takeover without duplicating conversation state", async () => {
    const port = new DeferredPlanningOnlyPort();
    const { database, authority, url } = await application(port);
    const leases = new ControlPlaneLeaseService(database);
    const resultText = "443/tcp open https";
    try {
      const pending = fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/interpret-result`,
        mutation("guided-takeover-in-flight", actionBody({
          result: {
            source: "paste",
            mediaType: "text/plain",
            byteSize: Buffer.byteLength(resultText, "utf8"),
            text: resultText,
          },
        })),
      );
      await port.started;
      expect(port.calls).toHaveLength(1);
      leases.release({
        runId: IDS.run,
        controlPlane: "ti_scale",
        leaseOwner: CONTROL_LEASE_OWNER,
        leaseToken: CONTROL_LEASE_TOKEN,
        now: new Date("2026-07-15T10:00:30.000Z"),
      });
      leases.acquire({
        runId: IDS.run,
        controlPlane: "ti_scale",
        leaseOwner: TAKEOVER_LEASE_OWNER,
        leaseToken: TAKEOVER_LEASE_TOKEN,
        ttlMs: 300_000,
        now: new Date("2026-07-15T10:00:31.000Z"),
      });
      authority.mode = "takeover";
      port.releaseAll();

      const response = await pending;
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({
        error: { code: "control_plane_lease_fence_invalid" },
      });
      // The operator-supplied observation was validly acquired before the
      // takeover; the stale provider response cannot interpret or converse.
      expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE event_type = 'guided.commander.interpret_result'
      `).get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT status, error_category FROM provider_turns").get())
        .toEqual({ status: "failed", error_category: "persistence_error" });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM settings
        WHERE key LIKE 'idempotency.guided-commander.%'
      `).get()).toEqual({ count: 0 });
    } finally {
      port.releaseAll();
      database.close();
    }
  });

  test("requires fresh authority for a memory replay and rechecks it inside the idempotent write transaction", async () => {
    const { database, authority, url } = await memoryApplication();
    const request = mutation("guided-memory-replay-authority", actionBody({
      sourceMessageId: IDS.initialMessage,
      nodeType: "preference",
      title: "Retain only under current Guided authority",
      summary: "Keep evidence explanations concise",
      scope: "global",
      sensitivity: "private",
    }));
    try {
      const first = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/remember`,
        request,
      );
      expect(first.status).toBe(201);
      const firstBody = await responseJson(first);
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get())
        .toEqual({ count: 1 });

      authority.mode = "missing";
      const replay = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/remember`,
        request,
      );
      expect(replay.status).toBe(409);
      expect(await replay.json()).toMatchObject({ error: { code: "control_plane_lease_missing" } });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get())
        .toEqual({ count: 1 });

      authority.mode = "valid";
      const suppressionRequest = mutation("guided-memory-suppression-replay-authority", actionBody({
        candidateId: firstBody.result.candidateId,
        reason: "Do not retain this candidate",
      }));
      const suppressed = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/do-not-remember`,
        suppressionRequest,
      );
      expect(suppressed.status).toBe(200);
      authority.mode = "missing";
      const suppressionReplay = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/do-not-remember`,
        suppressionRequest,
      );
      expect(suppressionReplay.status).toBe(409);
      expect(await suppressionReplay.json()).toMatchObject({
        error: { code: "control_plane_lease_missing" },
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get())
        .toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("aborts a memory write when authority is lost between its fast replay check and commit", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    seedGuidedRuntime(database);
    const service = new GuidedCommanderService({
      repository: new GuidedCommanderRepository(database),
    });
    let authorityChecks = 0;
    try {
      expect(() => service.remember({
        missionId: IDS.mission,
        request: {
          runId: IDS.run,
          stepId: IDS.step,
          expectedFingerprint: FINGERPRINT,
          sourceMessageId: IDS.initialMessage,
          nodeType: "preference",
          title: "Must not survive an authority race",
          summary: "No candidate may be committed",
          scope: "global",
          sensitivity: "private",
        },
        idempotencyKey: "guided-memory-transaction-race",
        actorId: "operator-test",
        assertMutationAuthority: () => {
          authorityChecks += 1;
          if (authorityChecks === 2) {
            throw new ControlPlaneLeaseError(
              "lease_fence_invalid",
              "The controller changed before the idempotent commit",
            );
          }
        },
      })).toThrow("controller changed");
      expect(authorityChecks).toBe(2);
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get())
        .toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM settings
        WHERE key LIKE 'idempotency.guided-commander.%'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("explains the exact represented step, persists context use, and replays idempotently", async () => {
    const { database, port, url } = await application();
    try {
      const request = mutation("guided-explain-0001", actionBody());
      const firstResponse = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/explain-more`,
        request,
      );
      expect(firstResponse.status).toBe(200);
      const first = await responseJson(firstResponse);
      expect(first.result).toMatchObject({
        action: "explain_more",
        actionFingerprint: FINGERPRINT,
        assistantMessage: {
          structuredContent: {
            executionPerformed: false,
            planMutated: false,
            nextConsequentialActionRequiresDecision: true,
          },
        },
      });
      expect(port.calls).toHaveLength(1);
      expect(port.calls[0]).toMatchObject({
        action: "explain_more",
        constraints: { executeTools: false, mutatePlan: false },
        step: { id: IDS.step, actionFingerprint: FINGERPRINT },
      });
      expect(port.calls[0]!.brainContext.items[0]).toMatchObject({
        nodeId: "memory-guided-explanation",
        summary: expect.stringContaining("concise evidence-led explanations"),
      });
      expect(port.calls[0]!.brainContext).toMatchObject({
        status: "ready",
        exposureReceiptId: expect.stringMatching(/^exposure_/u),
      });
      expect(JSON.stringify(port.calls[0]!.brainContext)).not.toContain("Explain why the evidence matters");
      expect(JSON.stringify(port.calls[0]!.brainContext)).not.toContain("LOCAL_ONLY_BODY_MUST_NOT_REACH_PROVIDER");
      expect(port.calls[0]!.brainContext.rejected).toContainEqual({
        reason: "provider_disclosure_not_approved",
        count: 1,
      });
      expect(database.prepare(`
        SELECT provider_turn_id, selected_context_ids_json, rejected_context_ids_json, blocked
        FROM provider_exposure_receipts
      `).get()).toMatchObject({
        provider_turn_id: expect.any(String),
        selected_context_ids_json: JSON.stringify(["memory-guided-explanation"]),
        rejected_context_ids_json: JSON.stringify(["memory-guided-local-only"]),
        blocked: 0,
      });

      const replay = await responseJson(await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/explain-more`,
        request,
      ));
      expect(replay).toEqual(first);
      expect(port.calls).toHaveLength(1);
      expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 3 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT used, influence_summary FROM memory_context_items
        WHERE context_pack_id = ? AND node_id = 'memory-guided-explanation'
      `).get(first.result.contextPackId)).toMatchObject({ used: 1, influence_summary: expect.any(String) });
      const transcript = await responseJson(await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/transcript?runId=${IDS.run}`,
      ));
      expect(transcript.currentStep).toMatchObject({ id: IDS.step, actionFingerprint: FINGERPRINT });
      expect(transcript.items).toHaveLength(3);
      expect(transcript.items.map((item: { role: string }) => item.role)).toEqual([
        "assistant",
        "operator",
        "assistant",
      ]);
    } finally {
      database.close();
    }
  });

  test("coalesces concurrent result interpretation before evidence, context, provider, or exchange side effects", async () => {
    const port = new DeferredPlanningOnlyPort();
    const { database, url } = await application(port);
    const key = "guided-concurrent-interpret-0001";
    const resultText = "443/tcp open https\nserver: bounded-lab";
    const request = mutation(key, actionBody({
      result: {
        source: "paste",
        mediaType: "text/plain",
        byteSize: Buffer.byteLength(resultText, "utf8"),
        text: resultText,
      },
    }));
    const counts = () => ({
      evidence: (database.prepare("SELECT COUNT(*) AS count FROM evidence").get() as { count: number }).count,
      contextPacks: (database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get() as { count: number }).count,
      providerTurns: (database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get() as { count: number }).count,
      messages: (database.prepare("SELECT COUNT(*) AS count FROM messages").get() as { count: number }).count,
    });
    try {
      const endpoint = `${url}/api/v2/guided/${IDS.mission}/commander/interpret-result`;
      const firstPending = fetch(endpoint, request);
      await port.started;
      expect(port.calls).toHaveLength(1);
      expect(counts()).toEqual({ evidence: 1, contextPacks: 1, providerTurns: 1, messages: 1 });

      const identicalPending = fetch(endpoint, request);
      const beforeConflict = counts();
      const conflictingText = "8443/tcp open https-alt";
      const conflictResponse = await fetch(endpoint, mutation(key, actionBody({
        result: {
          source: "paste",
          mediaType: "text/plain",
          byteSize: Buffer.byteLength(conflictingText, "utf8"),
          text: conflictingText,
        },
      })));
      expect(conflictResponse.status).toBe(409);
      expect(await conflictResponse.json()).toMatchObject({
        error: { code: "idempotency_key_conflict", retryable: false },
      });
      expect(port.calls).toHaveLength(1);
      expect(counts()).toEqual(beforeConflict);

      port.releaseAll();
      const [firstResponse, identicalResponse] = await Promise.all([firstPending, identicalPending]);
      expect(firstResponse.status).toBe(200);
      expect(identicalResponse.status).toBe(200);
      const [first, identical] = await Promise.all([
        responseJson(firstResponse),
        responseJson(identicalResponse),
      ]);
      expect(identical).toEqual(first);
      expect(port.calls).toHaveLength(1);
      expect(counts()).toEqual({ evidence: 1, contextPacks: 1, providerTurns: 1, messages: 3 });
      expect(database.prepare("SELECT status FROM provider_turns").get()).toEqual({ status: "completed" });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM messages WHERE role IN ('operator', 'assistant')
          AND id != ?
      `).get(IDS.initialMessage)).toEqual({ count: 2 });
      const brainHookAudit = database.prepare(`
        SELECT action, actor_type, actor_id, resource_id, details_json FROM audit_records
        WHERE action = 'brain.context_hook.invoked'
      `).get() as {
        action: string;
        actor_type: string;
        actor_id: string;
        resource_id: string;
        details_json: string;
      };
      expect(brainHookAudit).toMatchObject({
        action: "brain.context_hook.invoked",
        actor_type: "agent",
        actor_id: "guided-commander",
        resource_id: first.result.contextPackId,
      });
      expect(JSON.parse(brainHookAudit.details_json)).toMatchObject({
        hook: "phase_transition",
        status: "ready",
        contextPackId: first.result.contextPackId,
        availabilityPolicy: "degraded_allowed",
        retrievedCount: 2,
      });
    } finally {
      port.releaseAll();
      database.close();
    }
  });

  test("durably fences two Guided service instances before provider or conversation side effects", async () => {
    const directory = mkdtempSync(join(tmpdir(), "guided-commander-reservation-"));
    const filename = join(directory, "ti-scale.db");
    const database = createDatabaseConnection({ filename });
    migrateDatabase(database);
    seedGuidedRuntime(database);
    const secondDatabase = createDatabaseConnection({ filename });
    const port = new DeferredPlanningOnlyPort();
    const firstService = new GuidedCommanderService({
      repository: new GuidedCommanderRepository(database),
      port,
    });
    const secondService = new GuidedCommanderService({
      repository: new GuidedCommanderRepository(secondDatabase),
      port,
    });
    const request = {
      runId: IDS.run,
      stepId: IDS.step,
      expectedFingerprint: FINGERPRINT,
    };
    const key = "guided-cross-process-reservation-0001";
    const invoke = (service: GuidedCommanderService, note?: string) => service.respond({
      missionId: IDS.mission,
      action: "explain_more",
      request: { ...request, ...(note ? { note } : {}) },
      idempotencyKey: key,
      actorId: "operator-test",
      signal: new AbortController().signal,
      assertMutationAuthority: () => {},
    });
    const counts = () => ({
      contextPacks: (database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get() as { count: number }).count,
      providerTurns: (database.prepare("SELECT COUNT(*) AS count FROM provider_turns").get() as { count: number }).count,
      messages: (database.prepare("SELECT COUNT(*) AS count FROM messages").get() as { count: number }).count,
      events: (database.prepare("SELECT COUNT(*) AS count FROM events WHERE event_type = 'guided.commander.explain_more'").get() as { count: number }).count,
    });
    try {
      const firstPending = invoke(firstService);
      await port.started;
      expect(port.calls).toHaveLength(1);
      expect(counts()).toEqual({ contextPacks: 1, providerTurns: 1, messages: 1, events: 0 });

      await expect(invoke(secondService)).rejects.toMatchObject({
        status: 409,
        code: "guided_commander_request_in_progress",
        options: { retryable: true, details: { retryAfterMs: expect.any(Number) } },
      });
      await expect(invoke(secondService, "A conflicting request")).rejects.toMatchObject({
        status: 409,
        code: "idempotency_key_conflict",
      });
      expect(port.calls).toHaveLength(1);
      expect(counts()).toEqual({ contextPacks: 1, providerTurns: 1, messages: 1, events: 0 });

      port.releaseAll();
      const first = await firstPending;
      const replay = await invoke(secondService);
      expect(replay).toEqual(first);
      expect(port.calls).toHaveLength(1);
      expect(counts()).toEqual({ contextPacks: 1, providerTurns: 1, messages: 3, events: 1 });
    } finally {
      port.releaseAll();
      secondDatabase.close();
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("a failed durable owner releases only its own reservation so the same key can retry", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    seedGuidedRuntime(database);
    const port = new PlanningOnlyPort();
    port.response = () => {
      if (port.calls.length === 1) throw new Error("bounded provider failure");
      return {
        body: "The retry completed under a new durable owner without executing the represented action.",
        summary: "Guided explanation completed after a safe retry",
        confidence: 0.9,
        contextUse: [],
      };
    };
    const service = new GuidedCommanderService({
      repository: new GuidedCommanderRepository(database),
      port,
    });
    const request = {
      missionId: IDS.mission,
      action: "explain_more" as const,
      request: { runId: IDS.run, stepId: IDS.step, expectedFingerprint: FINGERPRINT },
      idempotencyKey: "guided-owner-failure-release-0001",
      actorId: "operator-test",
      signal: new AbortController().signal,
      assertMutationAuthority: () => {},
    };
    try {
      await expect(service.respond(request)).rejects.toMatchObject({
        code: "guided_commander_provider_failed",
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM settings
        WHERE key LIKE 'idempotency.guided-commander.%'
      `).get()).toEqual({ count: 0 });

      const completed = await service.respond(request);
      expect(completed.action).toBe("explain_more");
      expect(port.calls).toHaveLength(2);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM settings
        WHERE key LIKE 'idempotency.guided-commander.%'
      `).get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 3 });
    } finally {
      database.close();
    }
  });

  test("an expired Guided provider reservation is taken over and the stale owner cannot duplicate completion", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    seedGuidedRuntime(database);
    let nowMs = Date.parse("2026-07-15T10:00:00.000Z");
    const clock = () => new Date(nowMs);
    const port = new ExpiringOwnerPort();
    const firstRepository = new GuidedCommanderRepository(database, { clock });
    const secondRepository = new GuidedCommanderRepository(database, { clock });
    const firstService = new GuidedCommanderService({
      repository: firstRepository,
      port,
      options: { providerMutationLeaseMs: 1_000 },
    });
    const secondService = new GuidedCommanderService({
      repository: secondRepository,
      port,
      options: { providerMutationLeaseMs: 1_000 },
    });
    const request = {
      missionId: IDS.mission,
      action: "show_next_step" as const,
      request: { runId: IDS.run, stepId: IDS.step, expectedFingerprint: FINGERPRINT },
      idempotencyKey: "guided-expired-reservation-0001",
      actorId: "operator-test",
      signal: new AbortController().signal,
      assertMutationAuthority: () => {},
    };
    try {
      const stalePending = firstService.respond(request);
      await port.firstStarted;
      expect(port.calls).toHaveLength(1);

      nowMs += 1_001;
      const recovered = await secondService.respond(request);
      expect(port.calls).toHaveLength(2);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE event_type = 'guided.commander.show_next_step'
      `).get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 3 });

      port.releaseFirst();
      const stale = await stalePending;
      expect(stale).toEqual(recovered);
      expect(database.prepare("SELECT COUNT(*) AS count FROM messages").get()).toEqual({ count: 3 });
      expect(database.prepare(`
        SELECT status, error_category FROM provider_turns ORDER BY rowid
      `).all()).toEqual([
        { status: "cancelled", error_category: "idempotent_replay" },
        { status: "completed", error_category: null },
      ]);
      const contextRows = database.prepare(`
        SELECT p.message_id, i.used, i.influence_summary
        FROM memory_context_packs p
        JOIN memory_context_items i ON i.context_pack_id = p.id
        ORDER BY p.rowid
      `).all() as Array<{ message_id: string | null; used: number; influence_summary: string | null }>;
      expect(contextRows).toHaveLength(4);
      expect(contextRows.filter((row) => row.message_id === null && row.used === 0)).toHaveLength(2);
      expect(contextRows.filter((row) => row.message_id !== null && row.used === 1)).toHaveLength(1);
      expect(contextRows.filter((row) => row.message_id !== null && row.used === 0)).toHaveLength(1);

      // A stale owner cannot release a newer in-progress takeover.
      const directKey = "guided-owner-release-fence-0001";
      const directHash = "d".repeat(64);
      const oldOwner = firstRepository.reserveProviderMutation({
        scope: `explain_more:${IDS.mission}`,
        key: directKey,
        requestHash: directHash,
        actorId: "operator-test",
        leaseMs: 1_000,
        assertMutationAuthority: () => {},
      });
      expect(oldOwner.status).toBe("reserved");
      nowMs += 1_001;
      const newOwner = secondRepository.reserveProviderMutation({
        scope: `explain_more:${IDS.mission}`,
        key: directKey,
        requestHash: directHash,
        actorId: "operator-test",
        leaseMs: 1_000,
        assertMutationAuthority: () => {},
      });
      expect(newOwner.status).toBe("reserved");
      if (oldOwner.status !== "reserved" || newOwner.status !== "reserved") throw new Error("reservation fixture failed");
      expect(firstRepository.releaseProviderMutationReservation({
        scope: `explain_more:${IDS.mission}`,
        key: directKey,
        requestHash: directHash,
        ownerToken: oldOwner.ownerToken,
      })).toBe(false);
      expect(secondRepository.reserveProviderMutation({
        scope: `explain_more:${IDS.mission}`,
        key: directKey,
        requestHash: directHash,
        actorId: "operator-test",
        leaseMs: 1_000,
        assertMutationAuthority: () => {},
      })).toMatchObject({ status: "in_progress" });
      expect(secondRepository.releaseProviderMutationReservation({
        scope: `explain_more:${IDS.mission}`,
        key: directKey,
        requestHash: directHash,
        ownerToken: newOwner.ownerToken,
      })).toBe(true);
    } finally {
      port.releaseFirst();
      database.close();
    }
  });

  test("rejects a stale fingerprint before calling the planning provider", async () => {
    const { database, port, url } = await application();
    try {
      const response = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/show-next-step`,
        mutation("guided-stale-0001", actionBody({ expectedFingerprint: "c".repeat(64) })),
      );
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: { code: "guided_action_changed" } });
      expect(port.calls).toHaveLength(0);
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT status FROM guided_decisions WHERE id = ?").get(IDS.decision))
        .toEqual({ status: "pending" });
    } finally {
      database.close();
    }
  });

  test("requires mutation idempotency and enforces the bounded text-only ingestion contract", async () => {
    const { database, port, url } = await application();
    try {
      const missingKey = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/explain-more`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(actionBody()),
        },
      );
      expect(missingKey.status).toBe(400);
      expect(await missingKey.json()).toMatchObject({ error: { code: "idempotency_key_required" } });

      const oversized = "x".repeat(128 * 1024 + 1);
      const tooLarge = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/interpret-result`,
        mutation("guided-oversized-0001", actionBody({
          result: { source: "paste", mediaType: "text/plain", text: oversized },
        })),
      );
      expect(tooLarge.status).toBe(413);
      expect(await tooLarge.json()).toMatchObject({ error: { code: "guided_result_too_large" } });
      expect(port.calls).toHaveLength(0);
      expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("content-addresses and redacts a bounded text result without retaining authentication material", async () => {
    const { database, port, url } = await application();
    try {
      const raw = [
        "443/tcp open https",
        "Authorization: Bearer very-secret-bearer-value-12345",
        "password=hunter2",
      ].join("\n");
      const request = mutation("guided-interpret-0001", actionBody({
        result: {
          source: "paste",
          mediaType: "text/plain",
          byteSize: Buffer.byteLength(raw, "utf8"),
          text: raw,
        },
      }));
      const firstResponse = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/interpret-result`,
        request,
      );
      expect(firstResponse.status).toBe(200);
      const first = await responseJson(firstResponse);
      const evidenceId = String(first.result.evidenceId);
      expect(first).toMatchObject({
        ingestion: { multipartSupported: false, rawContentRetained: false },
        result: { actionFingerprint: FINGERPRINT },
      });
      expect(evidenceId).toStartWith("evidence_");
      expect(port.calls).toHaveLength(1);
      const providerPayload = JSON.stringify(port.calls[0]);
      expect(providerPayload).not.toContain("very-secret-bearer-value-12345");
      expect(providerPayload).not.toContain("hunter2");
      expect(providerPayload).toContain("REDACTED AUTHENTICATION MATERIAL");

      const evidence = database.prepare(`
        SELECT content_hash, provenance_json, extracted_text FROM evidence WHERE id = ?
      `).get(evidenceId) as {
        content_hash: string;
        provenance_json: string;
        extracted_text: string;
      };
      expect(evidence.content_hash).toBe(createHash("sha256").update(raw).digest("hex"));
      expect(evidence.extracted_text).not.toContain("hunter2");
      expect(evidence.extracted_text).not.toContain("very-secret");
      expect(JSON.parse(evidence.provenance_json)).toMatchObject({
        rawContentRetained: false,
        redactionCount: 2,
      });
      const serializedPersistence = [
        ...database.prepare("SELECT body AS value FROM messages").all() as Array<{ value: string }>,
        ...database.prepare("SELECT structured_content_json AS value FROM messages").all() as Array<{ value: string }>,
        ...database.prepare("SELECT value_json AS value FROM settings").all() as Array<{ value: string }>,
        ...database.prepare("SELECT payload_json AS value FROM events").all() as Array<{ value: string }>,
      ].map((row) => row.value).join("\n");
      expect(serializedPersistence).not.toContain("hunter2");
      expect(serializedPersistence).not.toContain("very-secret-bearer-value-12345");

      const replay = await responseJson(await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/interpret-result`,
        request,
      ));
      expect(replay).toEqual(first);
      expect(port.calls).toHaveLength(1);
      expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("creates only a reviewable memory candidate and supports do-not-relearn suppression", async () => {
    const { database, url } = await memoryApplication();
    try {
      const providerAction = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/show-next-step`,
        mutation("guided-provider-not-mounted-0001", actionBody()),
      );
      expect(providerAction.status).toBe(404);
      const rememberRequest = mutation("guided-remember-0001", actionBody({
        sourceMessageId: IDS.initialMessage,
        nodeType: "preference",
        title: "Prefer concise evidence explanations",
        summary: "Keep Guided explanations concise and evidence-led",
        content: "Explain why the evidence matters before the next represented action.",
        scope: "global",
        sensitivity: "private",
      }));
      const rememberedResponse = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/remember`,
        rememberRequest,
      );
      expect(rememberedResponse.status).toBe(201);
      const remembered = await responseJson(rememberedResponse);
      expect(remembered.result).toMatchObject({ status: "pending", sourceMessageId: IDS.initialMessage });
      expect(database.prepare(`
        SELECT status, proposed_scope FROM memory_candidates WHERE id = ?
      `).get(remembered.result.candidateId)).toEqual({ status: "pending", proposed_scope: "global" });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_nodes WHERE title = 'Prefer concise evidence explanations'
      `).get()).toEqual({ count: 0 });
      const rememberReplay = await responseJson(await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/remember`,
        rememberRequest,
      ));
      expect(rememberReplay).toEqual(remembered);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_candidates WHERE title = 'Prefer concise evidence explanations'
      `).get()).toEqual({ count: 1 });
      const memoryAudit = database.prepare(`
        SELECT id, mission_id, run_id, journey, actor_id, action, resource_type,
          resource_id, reason, details_json, previous_hash, record_hash, occurred_at
        FROM audit_records WHERE action = 'memory.candidate_created'
      `).get() as Record<string, string | null>;
      expect(memoryAudit).toMatchObject({
        mission_id: IDS.mission,
        run_id: IDS.run,
        journey: "guided",
      });
      const expectedAuditHash = createHash("sha256").update(canonicalJson({
        id: memoryAudit.id,
        previousHash: memoryAudit.previous_hash,
        missionId: memoryAudit.mission_id,
        runId: memoryAudit.run_id,
        journey: memoryAudit.journey,
        actorId: memoryAudit.actor_id,
        action: memoryAudit.action,
        resourceType: memoryAudit.resource_type,
        resourceId: memoryAudit.resource_id,
        reason: memoryAudit.reason,
        details: JSON.parse(memoryAudit.details_json!),
        occurredAt: memoryAudit.occurred_at,
      }), "utf8").digest("hex");
      expect(memoryAudit.record_hash).toBe(expectedAuditHash);

      const suppressedResponse = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/do-not-remember`,
        mutation("guided-suppress-0001", actionBody({
          candidateId: remembered.result.candidateId,
          reason: "Do not retain this collaboration preference",
        })),
      );
      expect(suppressedResponse.status).toBe(200);
      const suppressed = await responseJson(suppressedResponse);
      expect(suppressed.result).toMatchObject({
        candidateId: remembered.result.candidateId,
        status: "suppressed",
        suppressionId: expect.any(String),
      });
      expect(database.prepare("SELECT status FROM memory_candidates WHERE id = ?")
        .get(remembered.result.candidateId)).toEqual({ status: "suppressed" });

      const sensitive = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/remember`,
        mutation("guided-remember-secret-0001", actionBody({
          sourceMessageId: IDS.initialMessage,
          nodeType: "preference",
          title: "Unsafe candidate",
          summary: "api_key=do-not-store-this-value",
          scope: "global",
          sensitivity: "private",
        })),
      );
      expect(sensitive.status).toBe(422);
      expect(await sensitive.json()).toMatchObject({ error: { code: "sensitive_material_not_retained" } });
    } finally {
      database.close();
    }
  });

  test("an alternative request stays conversational and cannot mutate the plan or decision", async () => {
    const port = new PlanningOnlyPort();
    port.response = () => ({
      body: "A different in-scope strategy can be proposed, but it requires a versioned plan update before any action.",
      summary: "Compared an alternative without applying it",
      confidence: 0.72,
      recommendedNextStep: "Review whether to request a versioned plan change.",
      contextUse: [],
    });
    const { database, url } = await application(port);
    try {
      const response = await fetch(
        `${url}/api/v2/guided/${IDS.mission}/commander/use-another-approach`,
        mutation("guided-alternative-0001", actionBody({ note: "Prefer a passive validation path" })),
      );
      expect(response.status).toBe(200);
      const body = await responseJson(response);
      expect(body.result.assistantMessage.structuredContent).toMatchObject({
        action: "use_another_approach",
        executionPerformed: false,
        planMutated: false,
      });
      expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(IDS.run))
        .toEqual({ status: "waiting_guided_decision" });
      expect(database.prepare("SELECT status FROM plans WHERE id = ?").get(IDS.plan))
        .toEqual({ status: "active" });
      expect(database.prepare("SELECT status FROM guided_decisions WHERE id = ?").get(IDS.decision))
        .toEqual({ status: "pending" });
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });
});
