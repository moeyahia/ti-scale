import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import {
  AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS,
  AUTONOMOUS_ASSESSMENT_ACTION_TYPES,
  AUTONOMOUS_ASSESSMENT_PROOF_CONFIRMATION,
  AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
  AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS,
  AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA,
  assertAutonomousAssessmentAudit,
  assertAutonomousAssessmentReadiness,
  assertAutonomousAssessmentTargetConfinement,
  autonomousAssessmentTerminalCloseoutPending,
  autonomousAssessmentProofUsage,
  formatAutonomousAssessmentProofApiError,
  parseAutonomousAssessmentProofArguments,
  withDisposableAutonomousAssessmentTarget,
  waitForAutonomousAssessmentTerminalCloseout,
  type AutonomousAssessmentAuditSnapshot,
} from "../../../scripts/prove-autonomous-assessment-live";

function readiness() {
  return {
    schemaVersion: "2.4",
    status: "healthy",
    database: { healthy: true },
    eventStream: { status: "healthy" },
    execution: {
      autonomous: "ready",
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
    },
    dependencies: {
      autonomousRuntime: {
        status: "ready",
        readyActionClassIds: [...AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS],
        components: {
          localProcessExecution: true,
          mcpExecution: false,
          enforcingProvider: true,
          resultAwareSpecialistExecution: true,
          durableActionBoundary: true,
          exactRuntimeManifest: true,
        },
      },
      secondBrain: {
        status: "healthy",
        canonicalStoreAvailable: true,
        lexicalIndexAvailable: true,
        lexicalIndexSynchronized: true,
        vaultProjection: {
          status: "healthy",
          connectedConnections: 1,
          healthVerifiedConnections: 1,
        },
      },
    },
  };
}

function vault() {
  return {
    connections: [{
      id: "vault-active",
      displayName: "Ti-Scale Attack Knowledge Vault",
      vaultPath: "Attack-Knowledge-Vault",
      status: "connected",
      pathAvailable: true,
      trackedNoteCount: 2_307,
      healthChecks: { read: true, write: true, rename: true, delete: true },
    }],
  };
}

function auditSnapshot(
  options: Readonly<{ exploit?: boolean }> = {},
): AutonomousAssessmentAuditSnapshot {
  type AuditAction = AutonomousAssessmentAuditSnapshot["actions"][number];
  const exploit = options.exploit === true;
  const actionTypes = exploit
    ? AUTONOMOUS_ASSESSMENT_ACTION_TYPES
    : AUTONOMOUS_ASSESSMENT_ACTION_TYPES.slice(0, 7);
  const actions: AuditAction[] = actionTypes.flatMap<AuditAction>((actionType, index) => {
    const common: Omit<
      AuditAction,
      "id" | "parent_action_id" | "status" | "error_category"
    > = {
      step_id: `step-${index}`,
      assignment_id: `assignment-${index}`,
      action_type: actionType,
      action_class: AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS[index]!,
      fingerprint: `fingerprint-${index}`,
      result_summary: null,
      scoped_target: AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
      normalized_arguments_json: JSON.stringify({
        target: AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
      }),
      guided_decision_id: null,
      plan_version: index < 7 ? 1 : 2,
      ordinal: index < 7 ? index : 0,
      step_status: "completed",
      retry_count: 0,
    };
    if (index !== 2) {
      return [{
        ...common,
        id: `action-${index}`,
        parent_action_id: null,
        status: "succeeded",
        error_category: null,
      }];
    }
    return [{
      ...common,
      id: "action-2",
      parent_action_id: null,
      status: "failed",
      error_category: "transient_network",
    }, {
      ...common,
      id: "action-2-retry",
      parent_action_id: "action-2",
      status: "succeeded",
      error_category: null,
    }];
  });
  const contexts: AutonomousAssessmentAuditSnapshot["contexts"] = [
    { id: "ctx-intake", hook: "intake", action_id: null, used_count: 3 },
    { id: "ctx-planning", hook: "planning", action_id: null, used_count: 0 },
    { id: "ctx-finding", hook: "finding_validation", action_id: "action-5", used_count: 0 },
    { id: "ctx-evaluation", hook: "evaluation", action_id: null, used_count: 0 },
    { id: "ctx-lesson", hook: "lesson_proposal", action_id: null, used_count: 0 },
    { id: "ctx-reporting", hook: "reporting", action_id: null, used_count: 2 },
    { id: "ctx-closeout", hook: "closeout", action_id: null, used_count: 0 },
    ...actions.flatMap((action, index) => [
      {
        id: `ctx-assignment-${index}`,
        hook: "assignment_acceptance",
        action_id: action.id,
        used_count: 1,
      },
      {
        id: `ctx-tool-${index}`,
        hook: "tool_selection",
        action_id: action.id,
        used_count: 1,
      },
      {
        id: `ctx-phase-${index}`,
        hook: "phase_transition",
        action_id: action.id,
        used_count: 0,
      },
    ]),
    {
      id: "ctx-failure",
      hook: "failure",
      action_id: "action-2",
      used_count: 0,
    },
    ...(exploit
      ? [{
          id: "ctx-attack-attempt",
          hook: "attack_attempt",
          action_id: "action-7",
          used_count: 0,
        }]
      : []),
  ];
  const decision = (
    hook: "assignment_acceptance" | "tool_selection",
    index: number,
  ) => ({
    hook,
    decision: "attest_compatible",
    context_pack_id: `ctx-${hook === "assignment_acceptance" ? "assignment" : "tool"}-${index}`,
    applied_node_ids: [hook === "assignment_acceptance" ? "mem-agent" : `mem-tool-${index}`],
    representation_unchanged: true,
    scope_expanded: false,
    tool_changed: false,
    action_class_changed: false,
    arguments_changed: false,
    provider_exposure_created: false,
  });
  const syncedNodeIds = [
    "mem-agent",
    "mem-preference-autonomy",
    "mem-preference-readable",
    "mem-preference-evidence-first",
    ...actions.map((_action, index) => `mem-tool-${index}`),
  ];
  const usedMemoryNodes = syncedNodeIds.map((nodeId) => ({
    context_pack_id: nodeId.startsWith("mem-preference")
      ? nodeId === "mem-preference-autonomy"
        ? "ctx-intake"
        : "ctx-reporting"
      : nodeId === "mem-agent"
        ? "ctx-assignment-0"
        : `ctx-tool-${nodeId.split("-").at(-1)}`,
    hook: nodeId.startsWith("mem-preference")
      ? nodeId === "mem-preference-autonomy"
        ? "intake"
        : "reporting"
      : nodeId === "mem-agent"
        ? "assignment_acceptance"
        : "tool_selection",
    node_id: nodeId,
    lifecycle_status: nodeId.startsWith("mem-preference")
      ? "confirmed"
      : "verified",
    confirmation_state: nodeId.startsWith("mem-preference")
      ? "confirmed"
      : "not_required",
    active_vault_sync_status: "synced",
  }));
  const events: AutonomousAssessmentAuditSnapshot["events"] = [{
    event_type: "run.state_changed",
    payload_json: JSON.stringify({
      from: "running",
      to: "recovering",
      reason: "Bounded transient retry",
    }),
  }, {
    event_type: "action.completed",
    payload_json: JSON.stringify({
      actionId: "action-2",
      directive: "retry",
      retryAssignmentId: "assignment-2",
    }),
  }, {
    event_type: "run.completed",
    payload_json: "{}",
  }, {
    event_type: "brain.terminal_report_preferences_resolved",
    payload_json: JSON.stringify({
      contextPackId: "ctx-reporting",
      presentation: {
        narrativeStyle: "technical_readable",
        evidencePresentation: "evidence_first",
        appliedPreferenceNodeIds: [
          "mem-preference-readable",
          "mem-preference-evidence-first",
        ],
        appliedPreferenceKeys: [
          "communication.technical_readability",
          "communication.evidence_first",
        ],
      },
      safetyBoundary:
        "presentation_only_no_evidence_finding_scope_policy_or_deliverable_change",
    }),
  }, ...(exploit
    ? [{
        event_type: "plan.evidence_driven_expansion_applied",
        payload_json: JSON.stringify({
          attackAttemptId: "attempt-proof",
          contractAmended: false,
          memoryPolicyAmended: false,
        }),
      }]
    : [])];
  const cves = [{
    cve_id: "CVE-2024-6387",
    applicability: exploit ? "confirmed" : "possible",
    confidence: exploit ? 0.95 : 0.55,
  }];
  return {
    runStatus: "completed",
    runJourney: "autonomous",
    runRetryCount: 1,
    runBudgetUsage: { retries: 1 },
    contractActionPolicy: {
      allowedActionClasses: [...AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS],
      prohibitedActionClasses: [],
    },
    actions,
    toolCalls: actions.map(({ id, action_type, status, error_category }) => ({
      action_id: id,
      provider: action_type.includes("cve-applicability")
        ? "reviewed-local-intelligence"
        : action_type.includes("exploit-validation")
          ? "exact-target-sandbox"
        : "reviewed-local-process",
      tool_name: action_type,
      mcp_server_id: null,
      status,
      error_category,
      normalized_arguments_json: JSON.stringify({
        parentTarget: AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
      }),
    })),
    failureDiagnoses: [{
      id: "diagnosis-http-transient",
      action_id: "action-2",
      category: "target_unreachable",
      code: "autonomous_http_metadata_transient_network",
      retryable: 1,
      state: "active",
      resolved_at: null,
      automatic_recovery: {
        directive: "retry",
        retryPersisted: true,
      },
    }],
    providerTurnCount: 0,
    guidedDecisionCount: 0,
    approvalCount: 0,
    events,
    plans: exploit
      ? [{
          version: 1,
          strategy_summary:
            "Execute seven reviewed steps. Exploit validation remains deferred until its exact candidate gate is ready.",
          rationale_summary:
            "Exploit validation is deferred until current evidence is available.",
        }, {
          version: 2,
          strategy_summary: "Execute one exact evidence-matched validation.",
          rationale_summary:
            "Current evidence and one active-Vault procedure matched exactly.",
        }]
      : [{
          version: 1,
          strategy_summary:
            "Execute seven reviewed steps. Exploit validation remains deferred until its exact candidate gate is ready.",
          rationale_summary:
            "Exploit validation is deferred because no current exact candidate exists.",
        }],
    contexts,
    usedMemoryNodes,
    agentToolDecisions: actions.flatMap((_action, index) => [
      decision("assignment_acceptance", index),
      decision("tool_selection", index),
    ]),
    activeVaultSyncedNodeIds: syncedNodeIds,
    candidates: [{
      state: "candidate",
      promoted_evidence_id: null,
      observation_verification_state: "unverified",
    }],
    evidence: [{
      evidence_type: "configuration_snapshot",
      verification_state: "verified",
      summary: "The fixed assessment completed; matches remain unverified.",
      extracted_text: "{\"findingsCreated\":false}",
      provenance: {
        rawProcessOutputPromoted: false,
        findingsCreated: false,
      },
    }, ...["port_service_scan_result", "service_version_fingerprint"].map((evidence_type) => ({
      evidence_type,
      verification_state: "verified",
      summary: "Verified bounded TCP baseline phase.",
      extracted_text: null,
      provenance: {
        compositeToolId: "ti-scale:autonomous-full-tcp-baseline",
        phaseToolIds: [
          "kali:nmap-full-tcp-connect-discovery-v1",
          "kali:nmap-discovered-tcp-service-version-v1",
        ],
        rawProcessOutputPromoted: false,
      },
    })), {
      evidence_type: "service_version_fingerprint",
      verification_state: "verified",
      summary: "A later web fingerprint uses the same evidence taxonomy.",
      extracted_text: null,
      provenance: {
        virtualToolId: "ti-scale:autonomous-whatweb-fingerprint",
        rawProcessOutputPromoted: false,
      },
    }, {
      evidence_type: "cve_applicability",
      verification_state: "verified",
      summary: exploit
        ? "Current exact version evidence confirmed one applicable reviewed CVE."
        : "Current evidence produced no confirmed exact exploit candidate.",
      extracted_text: null,
      provenance: {
        sourceEvidenceIds: ["evidence-version"],
        applicabilityRecordIds: ["cve-record"],
        rawOutputPromoted: false,
        bannerOnlyConfirmationPermitted: false,
        targetInteraction: false,
      },
    }, ...(exploit
      ? [{
          evidence_type: "exploit_validation_result",
          verification_state: "verified",
          summary:
            "Independent target observation confirmed the reviewed exploit-impact assertion.",
          extracted_text: null,
          provenance: {
            attackAttemptId: "attempt-proof",
            exactTarget: AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
            independentVerifier: 1,
            rawOutputPromoted: 0,
            matched: true,
          },
        }]
      : []),
    ],
    rawVulnerabilityLogs: [{ technical_payload_json: "{\"stdout\":\"raw scanner output\"}" }],
    findings: [],
    cves,
    attackAttempts: exploit
      ? [{
          id: "attempt-proof",
          status: "succeeded",
          action_class: "exploit_validation",
          action_type: AUTONOMOUS_ASSESSMENT_ACTION_TYPES[7]!,
          scoped_target: AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
          outcome_summary: "Independent observer confirmed target impact.",
          started_at: "2026-07-23T10:00:00.000Z",
          ended_at: "2026-07-23T10:00:01.000Z",
          outcome_evidence_count: 1,
          outcome_evidence_id: "evidence-exploit-outcome",
          outcome_verification_state: "verified",
          outcome_source: "local:independent-http-outcome-observer",
          outcome_provenance: {
            attackAttemptId: "attempt-proof",
            exactTarget: AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
            independentVerifier: 1,
            rawOutputPromoted: 0,
            matched: true,
          },
        }]
      : [],
    evaluations: [{
      journey: "autonomous",
      metrics: {
        providerTurnCount: 0,
        guidedDecisionCount: 0,
        autonomousUserWaitCount: 0,
        retryCount: 1,
        recoveryCount: 1,
        recoverySuccessRate: 1,
        failedActions: 1,
        actionCount: actions.length,
        succeededActions: actionTypes.length,
      },
    }],
    reportArtifacts: [
      {
        artifact_type: "mission_report_markdown",
        content_hash: "a".repeat(64),
        storage_uri: `ti-scale-report://sha256/${"a".repeat(64)}/markdown`,
      },
      {
        artifact_type: "mission_report_json",
        content_hash: "b".repeat(64),
        storage_uri: `ti-scale-report://sha256/${"b".repeat(64)}/json`,
      },
    ],
    missionMemoryPolicy: {
      allowedScopes: ["confirmed_preferences"],
      exactContextNodeIds: [],
      intakeContext: {
        memoryInfluencedDefaults: true,
        safeOptionalDefaults: {
          autonomyPresentation: "high_autonomy",
          explanationTemplate: "technical_readable",
          reportTemplate: "evidence_first",
          safetyBoundary: "presentation_only_contract_unchanged",
        },
      },
    },
  };
}

describe("Autonomous Assessment production proof contract", () => {
  test("is assessment-only even when the optional exploit branch is authorized", () => {
    expect(AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA).toHaveLength(7);
    expect(
      AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA.join(" ")
        .toLocaleLowerCase("en-US"),
    ).not.toMatch(/\b(?:user\.txt|root\.txt|uid|gid|session lease)\b/u);
  });

  test("requires an explicit one-shot loopback proof confirmation", () => {
    expect(AUTONOMOUS_ASSESSMENT_PROOF_TARGET).toBe("127.0.0.2");
    expect(() => parseAutonomousAssessmentProofArguments([
      "--execute",
      "--confirm",
      AUTONOMOUS_ASSESSMENT_PROOF_CONFIRMATION,
    ])).not.toThrow();
    expect(() => parseAutonomousAssessmentProofArguments([]))
      .toThrow(autonomousAssessmentProofUsage());
    expect(() => parseAutonomousAssessmentProofArguments([
      "--execute",
      "--confirm",
      "wrong",
    ])).toThrow(autonomousAssessmentProofUsage());
  });

  test("rejects every action or tool argument that could address the legacy loopback host", () => {
    const valid = auditSnapshot();
    expect(() => assertAutonomousAssessmentTargetConfinement(valid))
      .not.toThrow();

    const actionEscaped = auditSnapshot();
    (actionEscaped.actions[0] as {
      scoped_target: string;
    }).scoped_target = "127.0.0.1";
    expect(() => assertAutonomousAssessmentTargetConfinement(actionEscaped))
      .toThrow("escaped the disposable target");

    const toolEscaped = auditSnapshot();
    (toolEscaped.toolCalls[0] as {
      normalized_arguments_json: string;
    }).normalized_arguments_json = JSON.stringify({
      origin: "http://127.0.0.1:3131",
    });
    expect(() => assertAutonomousAssessmentTargetConfinement(toolEscaped))
      .toThrow("could address the legacy loopback host");

    const localhostEscaped = auditSnapshot();
    (localhostEscaped.actions[0] as {
      normalized_arguments_json: string;
    }).normalized_arguments_json = JSON.stringify({ target: "localhost" });
    expect(() => assertAutonomousAssessmentTargetConfinement(localhostEscaped))
      .toThrow("could address the legacy loopback host");

    const mixedTarget = auditSnapshot();
    (mixedTarget.toolCalls[0] as {
      normalized_arguments_json: string;
    }).normalized_arguments_json = JSON.stringify({
      parentTarget: "127.0.0.2",
      fallbackOrigin: "http://127.0.0.1:3131",
    });
    expect(() => assertAutonomousAssessmentTargetConfinement(mixedTarget))
      .toThrow("could address the legacy loopback host");
  });

  test("always closes the disposable target when proof work fails", async () => {
    let closed = 0;
    const fixture = {
      host: "127.0.0.2" as const,
      port: 43_246,
      origin: "http://127.0.0.2:43246",
      requests: () => [],
      failureReceipt: () => ({
        enabled: true,
        injectedFailureCount: 1,
        recoveredCurlHeadCount: 1,
      }),
      close: async () => {
        closed += 1;
      },
    };
    await expect(withDisposableAutonomousAssessmentTarget(
      async () => {
        throw new Error("synthetic proof failure");
      },
      async () => fixture,
    )).rejects.toThrow("synthetic proof failure");
    expect(closed).toBe(1);
  });

  test("requires every assessment class plus a connected round-trip-tested Attack Knowledge Vault", () => {
    expect(assertAutonomousAssessmentReadiness(readiness(), vault())).toEqual({
      actionClassIds: [...AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS],
      activeVaultConnectionId: "vault-active",
      activeVaultName: "Ti-Scale Attack Knowledge Vault",
      baselinePlannerActionCount: 7,
      maximumPlannerActionCount: 8,
      baselineReviewedExecutionBindingCount: 8,
      maximumReviewedExecutionBindingCount: 9,
    });

    const missingClass = structuredClone(readiness());
    missingClass.dependencies.autonomousRuntime.readyActionClassIds.pop();
    expect(() => assertAutonomousAssessmentReadiness(missingClass, vault()))
      .toThrow("complete reviewed local Autonomous assessment path");

    const disconnected = structuredClone(vault());
    disconnected.connections[0]!.status = "degraded";
    expect(() => assertAutonomousAssessmentReadiness(readiness(), disconnected))
      .toThrow("not connected and round-trip healthy");
  });

  test("accepts only the exact zero-provider, zero-MCP, Vault-backed evidence-safe run", () => {
    expect(assertAutonomousAssessmentAudit(auditSnapshot())).toEqual({
      logicalActions: 7,
      durableActionAttempts: 8,
      reviewedExecutionBindings: 8,
      reviewedExecutionAttempts: 9,
      recoveredFailures: 1,
      retrySuccessors: 1,
      exploitValidationOutcome: "deferred_no_confirmed_current_evidence",
      attackAttempts: 0,
      providerTurns: 0,
      mcpToolCalls: 0,
      guidedDecisions: 0,
      approvals: 0,
      contextHooks: [...AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS],
      assignmentMemoryReceipts: 8,
      toolMemoryReceipts: 8,
      vaultBackedMemoryNodesUsed: 12,
      evidenceCandidates: 1,
      verifiedFindings: 0,
      cveRecords: 1,
      reportArtifacts: 2,
      intakePresentationPreferences: 3,
      reportPresentationPreferences: 2,
      targetConfinement: "127.0.0.2_only",
    });
  });

  test("accepts one evidence-matched validation only with independent target observation", () => {
    expect(assertAutonomousAssessmentAudit(auditSnapshot({ exploit: true }))).toEqual({
      logicalActions: 8,
      durableActionAttempts: 9,
      reviewedExecutionBindings: 9,
      reviewedExecutionAttempts: 10,
      recoveredFailures: 1,
      retrySuccessors: 1,
      exploitValidationOutcome: "independently_verified",
      attackAttempts: 1,
      providerTurns: 0,
      mcpToolCalls: 0,
      guidedDecisions: 0,
      approvals: 0,
      contextHooks: [...AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS],
      assignmentMemoryReceipts: 9,
      toolMemoryReceipts: 9,
      vaultBackedMemoryNodesUsed: 13,
      evidenceCandidates: 1,
      verifiedFindings: 0,
      cveRecords: 1,
      reportArtifacts: 2,
      intakePresentationPreferences: 3,
      reportPresentationPreferences: 2,
      targetConfinement: "127.0.0.2_only",
    });

    const forged = auditSnapshot({ exploit: true });
    forged.attackAttempts[0]!.outcome_provenance!.independentVerifier = 0;
    expect(() => assertAutonomousAssessmentAudit(forged))
      .toThrow("not exactly one independently verified attempt");
  });

  test("rejects provider or Guided dependence and missing lifecycle Context Packs", () => {
    const providerBase = auditSnapshot();
    const provider = {
      ...providerBase,
      providerTurnCount: 1,
    };
    expect(() => assertAutonomousAssessmentAudit(provider))
      .toThrow("crossed a Guided, provider, MCP, or approval boundary");

    const reportingBase = auditSnapshot();
    const missingReporting = {
      ...reportingBase,
      contexts: reportingBase.contexts.filter(({ hook }) => hook !== "reporting"),
    };
    expect(() => assertAutonomousAssessmentAudit(missingReporting))
      .toThrow("Required Brain lifecycle Context Pack is missing: reporting");
  });

  test("rejects broken retry lineage, missing diagnosis, and missing failure memory", () => {
    const wrongParentBase = auditSnapshot();
    const wrongParent = {
      ...wrongParentBase,
      actions: wrongParentBase.actions.map((action) =>
        action.id === "action-2-retry"
          ? { ...action, parent_action_id: "action-unrelated" }
          : action),
    };
    expect(() => assertAutonomousAssessmentAudit(wrongParent))
      .toThrow("failed-parent/succeeded-child lineage");

    const noDiagnosis = {
      ...auditSnapshot(),
      failureDiagnoses: [],
    };
    expect(() => assertAutonomousAssessmentAudit(noDiagnosis))
      .toThrow("no exact retryable structured diagnosis");

    const nonRetryableBase = auditSnapshot();
    const nonRetryable = {
      ...nonRetryableBase,
      failureDiagnoses: nonRetryableBase.failureDiagnoses.map((diagnosis) => ({
        ...diagnosis,
        retryable: 0,
      })),
    };
    expect(() => assertAutonomousAssessmentAudit(nonRetryable))
      .toThrow("no exact retryable structured diagnosis");

    const noFailureContextBase = auditSnapshot();
    const noFailureContext = {
      ...noFailureContextBase,
      contexts: noFailureContextBase.contexts.filter(({ hook }) =>
        hook !== "failure"),
    };
    expect(() => assertAutonomousAssessmentAudit(noFailureContext))
      .toThrow("exactly one failure Context Pack");
  });

  test("rejects memory not synchronized to the active Vault or any representation mutation", () => {
    const vaultBase = auditSnapshot();
    const unsynchronized = {
      ...vaultBase,
      activeVaultSyncedNodeIds: ["mem-agent"],
    };
    expect(() => assertAutonomousAssessmentAudit(unsynchronized))
      .toThrow("Every memory item actually used");

    const mutationBase = auditSnapshot();
    const mutated = {
      ...mutationBase,
      agentToolDecisions: mutationBase.agentToolDecisions.map((decision, index) =>
        index === 0 ? { ...decision, arguments_changed: true } : decision),
    };
    expect(() => assertAutonomousAssessmentAudit(mutated))
      .toThrow("unchanged active-Vault-backed compatibility attestation");
  });

  test("rejects scanner auto-promotion, automatic findings, and CVE overclaiming", () => {
    const candidateBase = auditSnapshot();
    const promoted = {
      ...candidateBase,
      candidates: candidateBase.candidates.map((candidate, index) => index === 0
        ? {
            ...candidate,
            state: "promoted",
            promoted_evidence_id: "evidence-promoted",
          }
        : candidate),
    };
    expect(() => assertAutonomousAssessmentAudit(promoted))
      .toThrow("exclusively as unverified evidence candidates");

    const finding = {
      ...auditSnapshot(),
      findings: [{ review_status: "verified" }],
    };
    expect(() => assertAutonomousAssessmentAudit(finding))
      .toThrow("automatically created a finding");

    const cveBase = auditSnapshot();
    const confirmedCve = {
      ...cveBase,
      cves: cveBase.cves.map((cve, index) =>
        index === 0 ? { ...cve, applicability: "confirmed" } : cve),
    };
    expect(() => assertAutonomousAssessmentAudit(confirmedCve))
      .toThrow("neither independently verified nor explicitly deferred");

    const tcpBase = auditSnapshot();
    const missingServicePhase = {
      ...tcpBase,
      evidence: tcpBase.evidence.map((evidence) =>
        evidence.evidence_type === "service_version_fingerprint"
          ? { ...evidence, provenance: { ...evidence.provenance, phaseToolIds: [] } }
          : evidence),
    };
    expect(() => assertAutonomousAssessmentAudit(missingServicePhase))
      .toThrow("both reviewed physical phase bindings");

    const notApplicable = auditSnapshot();
    const webSurfaceNotRecognized = {
      ...notApplicable,
      actions: notApplicable.actions.map((action) =>
        action.action_type === AUTONOMOUS_ASSESSMENT_ACTION_TYPES[6]
          ? {
              ...action,
              result_summary:
                "No responding HTTP origin was available; the bounded assessment was not applicable.",
            }
          : action),
      rawVulnerabilityLogs: [],
    };
    expect(() => assertAutonomousAssessmentAudit(webSurfaceNotRecognized))
      .toThrow("was not recognized as an HTTP origin");
  });

  test("waits read-only for every asynchronous terminal closeout record", async () => {
    const complete = auditSnapshot();
    const snapshots: AutonomousAssessmentAuditSnapshot[] = [
      { ...complete, evaluations: [] },
      {
        ...complete,
        contexts: complete.contexts.filter(({ hook }) => hook !== "reporting"),
      },
      {
        ...complete,
        events: complete.events.filter(({ event_type }) =>
          event_type !== "brain.terminal_report_preferences_resolved"),
      },
      {
        ...complete,
        reportArtifacts: complete.reportArtifacts.filter(({ artifact_type }) =>
          artifact_type !== "mission_report_markdown"),
      },
      {
        ...complete,
        usedMemoryNodes: complete.usedMemoryNodes.map((node, index) =>
          index === 0
            ? { ...node, active_vault_sync_status: "database_ahead" }
            : node),
      },
      complete,
    ];
    let reads = 0;
    let sleeps = 0;
    let clock = 0;
    const observed = await waitForAutonomousAssessmentTerminalCloseout(
      "run-proof",
      "mission-proof",
      "vault-active",
      {
        timeoutMs: 1_000,
        pollIntervalMs: 1,
        now: () => clock,
        sleep: async (milliseconds) => {
          sleeps += 1;
          clock += milliseconds;
        },
        readSnapshot: () => snapshots[Math.min(reads++, snapshots.length - 1)]!,
      },
    );
    expect(observed).toBe(complete);
    expect(reads).toBe(6);
    expect(sleeps).toBe(5);
    expect(autonomousAssessmentTerminalCloseoutPending(complete)).toEqual([]);
  });

  test("diagnoses incomplete closeout and rejects a non-content-addressed report", async () => {
    const incomplete = {
      ...auditSnapshot(),
      evaluations: [],
      contexts: [],
      events: [{ event_type: "run.completed", payload_json: "{}" }],
      reportArtifacts: [],
    };
    expect(autonomousAssessmentTerminalCloseoutPending(incomplete)).toContain(
      "terminal evaluation",
    );
    await expect(waitForAutonomousAssessmentTerminalCloseout(
      "run-proof",
      "mission-proof",
      "vault-active",
      {
        timeoutMs: 0,
        readSnapshot: () => incomplete,
      },
    )).rejects.toThrow("still waiting for: terminal evaluation");

    const malformed = auditSnapshot();
    const wrongUri = {
      ...malformed,
      reportArtifacts: malformed.reportArtifacts.map((artifact, index) =>
        index === 0 ? { ...artifact, storage_uri: "file:///tmp/report.md" } : artifact),
    };
    expect(() => autonomousAssessmentTerminalCloseoutPending(wrongUri))
      .toThrow("failed its immutable content-addressed binding");
  });

  test("reads the canonical nested V2 error envelope and keeps flat compatibility", () => {
    expect(formatAutonomousAssessmentProofApiError(
      "/api/v2/missions",
      409,
      {
        error: {
          code: "control_plane_conflict",
          message: "Control plane conflict",
          humanMessage: "Another control plane owns this run.",
          remediation: "Open the owning control plane.",
          traceId: "trace-proof-01",
        },
      },
    )).toBe(
      "/api/v2/missions failed (409, control_plane_conflict): Another control plane owns this run. Remediation: Open the owning control plane. Trace: trace-proof-01",
    );
    expect(formatAutonomousAssessmentProofApiError(
      "/api/v2/health",
      503,
      { code: "legacy_flat", humanMessage: "The service is starting." },
    )).toBe(
      "/api/v2/health failed (503, legacy_flat): The service is starting.",
    );
  });

  test("does not call the operator report-generation mutation after terminal completion", () => {
    const source = readFileSync(
      new URL("../../../scripts/prove-autonomous-assessment-live.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toContain("/reports/runs/${encodeURIComponent(runId)}/generate");
    expect(source).not.toContain("autonomous-assessment-report-");
  });
});
