import { request as httpRequest } from "node:http";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import {
  COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS,
  COMPLETE_AUTONOMOUS_ACTION_TYPES,
  COMPLETE_AUTONOMOUS_CANDIDATE_TRANSPORT_UNAVAILABLE,
  COMPLETE_AUTONOMOUS_LIVE_PROOF_CONFIRMATION,
  COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES,
  COMPLETE_AUTONOMOUS_SUCCESS_CRITERIA,
  CompleteAutonomousLivePrerequisiteError,
  assertCompleteAutonomousActionAudit,
  assertCompleteAutonomousLivePrerequisites,
  assertDisposableCompleteTargetTrace,
  buildCompleteAutonomousResolveInput,
  completeAutonomousLiveProofUsage,
  inspectCompleteAutonomousLiveEnvironment,
  parseCompleteAutonomousLiveProofArguments,
  withDisposableCompleteAutonomousTarget,
} from "../../../scripts/prove-complete-autonomous-live";
import type {
  AutonomousAssessmentAuditSnapshot,
} from "../../../scripts/prove-autonomous-assessment-live";
import {
  AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS,
  AUTONOMOUS_ASSESSMENT_ACTION_TYPES,
} from "../../../scripts/prove-autonomous-assessment-live";
import {
  DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
  DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER_HEADER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
  DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
  DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
  DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
  startDisposableCompleteAutonomousTarget,
  type DisposableCompleteAutonomousTarget,
} from "../../../server/autonomous-runtime/testing/DisposableCompleteAutonomousTarget";

function health() {
  return {
    schemaVersion: "2.4",
    status: "healthy",
    database: { healthy: true },
    eventStream: { status: "healthy" },
  };
}

function readiness(
  actionClassIds: readonly string[] =
    COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS,
) {
  return {
    schemaVersion: "2.4",
    status: "healthy",
    execution: {
      autonomous: "ready",
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
    },
    dependencies: {
      autonomousRuntime: {
        status: "ready",
        readyActionClassIds: [...actionClassIds],
        components: {
          localProcessExecution: true,
          enforcingProvider: true,
          resultAwareSpecialistExecution: true,
          durableActionBoundary: true,
          exactRuntimeManifest: true,
        },
      },
    },
  };
}

function vault() {
  return {
    enabled: true,
    connections: [{
      id: "vault-active",
      displayName: "Ti-Scale Attack Knowledge Vault",
      vaultPath: "Attack-Knowledge-Vault",
      status: "connected",
      pathAvailable: true,
      trackedNoteCount: 2_400,
      healthChecks: {
        read: true,
        write: true,
        rename: true,
        delete: true,
      },
    }],
    syncStates: [{
      connectionId: "vault-active",
      nodeId: "memory-capability",
      status: "synced",
    }],
  };
}

const ACTION_CLASS_BY_TYPE = new Map<string, string>([
  ...AUTONOMOUS_ASSESSMENT_ACTION_TYPES.map((actionType, index) =>
    [actionType, AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS[index]!] as const),
  [
    "autonomous_linux_session_identity_v1",
    "command_session_execution",
  ],
  [
    "autonomous_linux_user_flag_hash_proof_v1",
    "data_access_impact_validation",
  ],
  [
    "autonomous_linux_privilege_escalation_v1",
    "privilege_escalation",
  ],
  [
    "autonomous_linux_root_flag_hash_proof_v1",
    "data_access_impact_validation",
  ],
  [
    "autonomous_linux_session_cleanup_v1",
    "cleanup_restoration",
  ],
]);

function actionSnapshot(): AutonomousAssessmentAuditSnapshot {
  type Action = AutonomousAssessmentAuditSnapshot["actions"][number];
  const actions: Action[] = COMPLETE_AUTONOMOUS_ACTION_TYPES.map(
    (actionType, index) => ({
      id: `action-${index}`,
      step_id: `step-${index}`,
      assignment_id: `assignment-${index}`,
      parent_action_id: null,
      action_type: actionType,
      action_class: ACTION_CLASS_BY_TYPE.get(actionType)!,
      fingerprint: `fingerprint-${index}`,
      status: "succeeded",
      result_summary: "Succeeded inside the disposable proof",
      error_category: null,
      retry_count: 0,
      scoped_target: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      normalized_arguments_json: JSON.stringify({
        target: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      }),
      guided_decision_id: null,
      plan_version: index < 7 ? 1 : 2,
      ordinal: index < 7 ? index : index - 7,
      step_status: "completed",
    }),
  );
  const toolCalls: AutonomousAssessmentAuditSnapshot["toolCalls"] =
    actions.map((action) => ({
      action_id: action.id,
      provider: COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES.includes(
        action.action_type as
          (typeof COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES)[number],
      )
        ? "candidate-linux-session"
        : action.action_class === "exploit_validation"
          ? "exact-target-sandbox"
          : action.action_class
              === "cve_intelligence_applicability_validation"
            ? "reviewed-local-intelligence"
            : "reviewed-local-process",
      tool_name: action.action_type,
      mcp_server_id: null,
      status: "succeeded",
      error_category: null,
      normalized_arguments_json: action.normalized_arguments_json,
    }));
  return {
    runStatus: "completed",
    runJourney: "autonomous",
    runRetryCount: 0,
    runBudgetUsage: {},
    contractActionPolicy: {
      allowedActionClasses: [...COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS],
      prohibitedActionClasses: [],
    },
    actions,
    toolCalls,
    failureDiagnoses: [],
    providerTurnCount: 0,
    guidedDecisionCount: 0,
    approvalCount: 0,
    events: [],
    plans: [],
    contexts: [],
    usedMemoryNodes: [],
    agentToolDecisions: [],
    activeVaultSyncedNodeIds: [],
    candidates: [],
    evidence: [],
    rawVulnerabilityLogs: [],
    findings: [],
    cves: [],
    attackAttempts: [],
    evaluations: [],
    reportArtifacts: [],
    missionMemoryPolicy: {},
  };
}

function rawGet(
  origin: string,
  path: string,
  headers: Readonly<Record<string, string>> = {},
): Promise<Readonly<{
  status: number;
  headers: import("node:http").IncomingHttpHeaders;
  body: string;
}>> {
  const url = new URL(origin);
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: url.hostname,
      port: Number(url.port),
      method: "GET",
      path,
      headers,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.once("end", () => resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.once("error", reject);
    request.end();
  });
}

describe("Complete Autonomous production-API proof", () => {
  test("requires the exact explicit one-mission execution confirmation", () => {
    expect(() => parseCompleteAutonomousLiveProofArguments([]))
      .toThrow("creates exactly one authorized disposable-loopback");
    expect(() => parseCompleteAutonomousLiveProofArguments([
      "--execute",
      "--confirm",
      `${COMPLETE_AUTONOMOUS_LIVE_PROOF_CONFIRMATION}-wrong`,
    ])).toThrow(completeAutonomousLiveProofUsage());
    expect(parseCompleteAutonomousLiveProofArguments([
      "--execute",
      "--confirm",
      COMPLETE_AUTONOMOUS_LIVE_PROOF_CONFIRMATION,
    ])).toBeUndefined();
  });

  test("builds only the exact disposable full-path contract", () => {
    const input = buildCompleteAutonomousResolveInput();
    expect(input).toMatchObject({
      journey: "autonomous",
      authorizationAcknowledged: true,
      templateId: "htb_web_full_path",
      environmentClassification: "local_disposable_lab",
      destructivePolicy: "bounded_lab_only",
      targets: [{
        value: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
        type: "host",
      }],
      successCriteria: [...COMPLETE_AUTONOMOUS_SUCCESS_CRITERIA],
    });
    expect(input.objective).toContain("hash-only");
    const policy = input.actionPolicyOverrides as Record<string, string>;
    for (const actionClassId of COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS) {
      expect(policy[actionClassId]).toBe("pre_authorized");
    }
    expect(policy.denial_of_service_disruption).toBe("prohibited");
    expect(policy.destructive_modification).toBe("prohibited");
  });

  test("requires the live candidate transport and connected Vault before mission creation", async () => {
    expect(assertCompleteAutonomousLivePrerequisites({
      health: health(),
      readiness: readiness(),
      vault: vault(),
      databaseSchemaVersion: 63,
    })).toMatchObject({
      databaseSchemaVersion: 63,
      activeVaultConnectionId: "vault-active",
      fixtureOnly: true,
      realTargetSupportClaimed: false,
    });

    const assessmentOnlyClasses =
      COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS.filter((actionClassId) =>
        ![
          "command_session_execution",
          "data_access_impact_validation",
          "privilege_escalation",
          "cleanup_restoration",
        ].includes(actionClassId));
    expect(() => assertCompleteAutonomousLivePrerequisites({
      health: health(),
      readiness: readiness(assessmentOnlyClasses),
      vault: vault(),
      databaseSchemaVersion: 60,
    })).toThrow(CompleteAutonomousLivePrerequisiteError);
    try {
      assertCompleteAutonomousLivePrerequisites({
        health: health(),
        readiness: readiness(assessmentOnlyClasses),
        vault: vault(),
        databaseSchemaVersion: 60,
      });
      throw new Error("missing candidate transport was accepted");
    } catch (error) {
      expect(error).toBeInstanceOf(CompleteAutonomousLivePrerequisiteError);
      expect(
        (error as CompleteAutonomousLivePrerequisiteError).code,
      ).toBe(COMPLETE_AUTONOMOUS_CANDIDATE_TRANSPORT_UNAVAILABLE);
    }

    const requested: string[] = [];
    const client = {
      request: async (path: string) => {
        requested.push(path);
        if (path === "/api/v2/health") return health();
        if (path === "/api/v2/system/readiness") {
          return readiness(assessmentOnlyClasses);
        }
        if (path === "/api/v2/brain/vault") return vault();
        throw new Error(`unexpected mutation path ${path}`);
      },
    };
    await expect(
      inspectCompleteAutonomousLiveEnvironment(client, 60),
    ).rejects.toMatchObject({
      code: COMPLETE_AUTONOMOUS_CANDIDATE_TRANSPORT_UNAVAILABLE,
    });
    expect(new Set(requested)).toEqual(new Set([
      "/api/v2/health",
      "/api/v2/system/readiness",
      "/api/v2/brain/vault",
    ]));
    expect(requested).not.toContain("/api/v2/missions");
  });

  test("accepts only the exact ordered 13-action production-runtime chain", () => {
    const baseline = actionSnapshot();
    expect(assertCompleteAutonomousActionAudit(baseline)).toEqual({
      logicalSucceededActions: 13,
      durableActionAttempts: 13,
    });

    const privilegeIndex = baseline.actions.findIndex(({ action_type }) =>
      action_type === "autonomous_linux_privilege_escalation_v1");
    const rootIndex = baseline.actions.findIndex(({ action_type }) =>
      action_type === "autonomous_linux_root_flag_hash_proof_v1");
    const reordered = {
      ...baseline,
      actions: baseline.actions.map((action, index) =>
        index === privilegeIndex
          ? baseline.actions[rootIndex]!
          : index === rootIndex
            ? baseline.actions[privilegeIndex]!
            : action),
    } satisfies AutonomousAssessmentAuditSnapshot;
    expect(() => assertCompleteAutonomousActionAudit(reordered))
      .toThrow("did not preserve the reviewed");

    const harnessProvider = {
      ...baseline,
      toolCalls: baseline.toolCalls.map((call, index) =>
        index === baseline.toolCalls.length - 1
          ? { ...call, provider: "loopback-test-harness" }
          : call),
    } satisfies AutonomousAssessmentAuditSnapshot;
    expect(() => assertCompleteAutonomousActionAudit(harnessProvider))
      .toThrow("did not match its action");
  });

  test("serves recon, one fixed impact marker, typed hash-only proofs, and cleanup without host operations", async () => {
    const target = await startDisposableCompleteAutonomousTarget(0);
    try {
      expect(target).toMatchObject({
        host: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
        fixtureOnly: true,
        disposableSimulationOnly: true,
        realTargetSupport: false,
        arbitraryExternalTargetSupport: false,
        hostFileReads: false,
        commandExecution: false,
      });
      const home = await rawGet(target.origin, "/");
      expect(home.status).toBe(200);
      expect(home.headers.server).toBe(
        `${DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT}/`
        + DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
      );
      expect(home.body).toContain("Authorized disposable loopback lab");

      const impact = await rawGet(
        target.origin,
        DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
        {
          [DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER_HEADER]:
            DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER,
        },
      );
      expect(impact.status).toBe(200);
      expect(JSON.parse(impact.body)).toMatchObject({
        fixtureOnly: true,
        realTargetSupport: false,
        marker: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
        observationRole: "reviewed_fixture_trigger",
      });
      const independentImpact = await rawGet(
        target.origin,
        DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
      );
      expect(JSON.parse(independentImpact.body)).toMatchObject({
        marker: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
        observationRole: "independent_outcome_observation",
      });

      const sessionArtifactId = "session-disposable-proof";
      const post = async (
        path: string,
        body: Readonly<Record<string, unknown>>,
      ) => {
        const response = await fetch(`${target.origin}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        return {
          status: response.status,
          body: await response.json() as Record<string, unknown>,
        };
      };
      expect(await post("/ti-scale/session/open", {
        exactTarget: target.host,
        sessionArtifactId,
      })).toMatchObject({ status: 200, body: { accepted: true } });

      const identity = await fetch(
        `${target.origin}/ti-scale/session/identity`
        + `?exactTarget=${target.host}`
        + `&sessionArtifactId=${sessionArtifactId}`,
      );
      expect(await identity.json()).toMatchObject({
        principal: "fixtureuser",
        uid: 1_000,
        gid: 1_000,
      });

      const userProof = await post("/ti-scale/session/user-flag-proof", {
        exactTarget: target.host,
        sessionArtifactId,
        declaredPath: "/home/fixtureuser/user.txt",
        returnContent: false,
      });
      expect(userProof).toMatchObject({
        status: 200,
        body: {
          declaredPath: "/home/fixtureuser/user.txt",
          byteSize: 32,
          contentReturned: false,
        },
      });
      expect(userProof.body.sha256).toMatch(/^[a-f0-9]{64}$/u);

      expect(await post("/ti-scale/session/privilege-escalation", {
        sessionArtifactId,
        operation: "privilege_escalation",
      })).toMatchObject({
        status: 200,
        body: { accepted: true },
      });

      const rootIdentity = await fetch(
        `${target.origin}/ti-scale/session/root-identity`
        + `?sessionArtifactId=${sessionArtifactId}`,
      );
      expect(await rootIdentity.json()).toMatchObject({
        principal: "root",
        uid: 0,
        gid: 0,
      });

      const rootProof = await post("/ti-scale/session/root-flag-proof", {
        sessionArtifactId,
        operation: "root_flag_hash_proof",
        declaredPath: "/root/root.txt",
        returnContent: false,
      });
      expect(rootProof).toMatchObject({
        status: 200,
        body: {
          declaredPath: "/root/root.txt",
          byteSize: 32,
          contentReturned: false,
        },
      });
      expect(rootProof.body.contentSha256).toMatch(/^[a-f0-9]{64}$/u);

      expect(await post("/ti-scale/session/cleanup", {
        sessionArtifactId,
        operation: "cleanup",
      })).toMatchObject({
        status: 200,
        body: { closed: true },
      });
      expect(target.openSessionCount()).toBe(0);
      expect(target.traces().map(({ result }) => result)).toEqual([
        "recon_response",
        "fixed_impact_triggered",
        "fixed_impact_disclosed",
        "session_opened",
        "user_identity_observed",
        "user_hash_proved",
        "privilege_continued",
        "root_identity_observed",
        "root_hash_proved",
        "session_closed",
      ]);
      expect(DISPOSABLE_COMPLETE_AUTONOMOUS_CVE).toBe("CVE-2021-41773");
    } finally {
      await target.close();
    }
  });

  test("requires the fixed production-port trace and always closes the fixture", async () => {
    let closed = 0;
    const traces = [{
      sequence: 1,
      method: "GET",
      path: "/",
      phase: "recon" as const,
      actionId: null,
      fixtureMarker: null,
      result: "recon_response" as const,
    }, {
      sequence: 2,
      method: "GET",
      path: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
      phase: "exploit_validation" as const,
      actionId: null,
      fixtureMarker: DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER,
      result: "fixed_impact_triggered" as const,
    }, {
      sequence: 3,
      method: "GET",
      path: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
      phase: "exploit_validation" as const,
      actionId: null,
      fixtureMarker: null,
      result: "fixed_impact_disclosed" as const,
    }];
    const fixed = {
      schemaVersion:
        "ti-scale.disposable-complete-autonomous-target.v1" as const,
      host: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      port: 8_080,
      origin: `http://${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:8080`,
      fixtureOnly: true as const,
      disposableSimulationOnly: true as const,
      realTargetSupport: false as const,
      arbitraryExternalTargetSupport: false as const,
      hostFileReads: false as const,
      commandExecution: false as const,
      traces: () => traces,
      openSessionCount: () => 0,
      close: async () => {
        closed += 1;
      },
    } satisfies DisposableCompleteAutonomousTarget;
    expect(assertDisposableCompleteTargetTrace(fixed)).toEqual({
      observedRequestCount: 3,
      reconRequestCount: 1,
      exploitTriggerRequestCount: 1,
      exploitMarkerRequestCount: 1,
      typedSessionRequestCount: 0,
      openSessionCount: 0,
      impactMarker: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
    });
    await expect(withDisposableCompleteAutonomousTarget(
      async () => {
        throw new Error("synthetic complete proof failure");
      },
      async () => fixed,
    )).rejects.toThrow("synthetic complete proof failure");
    expect(closed).toBe(1);
  });

  test("contains one mission-creation call and starts the target only after the live prerequisite", () => {
    const source = readFileSync(
      new URL(
        "../../../scripts/prove-complete-autonomous-live.ts",
        import.meta.url,
      ),
      "utf8",
    );
    expect(source.match(
      /client\.request\("\/api\/v2\/missions", \{/gu,
    )).toHaveLength(1);
    const prerequisite = source.indexOf(
      "await inspectCompleteAutonomousLiveEnvironment(client)",
    );
    const fixture = source.indexOf(
      "return withDisposableCompleteAutonomousTarget",
    );
    expect(prerequisite).toBeGreaterThan(-1);
    expect(fixture).toBeGreaterThan(prerequisite);
    expect(source).not.toContain("http://127.0.0.1:3131");
    expect(source).not.toContain("localhost:3131");
  });
});
