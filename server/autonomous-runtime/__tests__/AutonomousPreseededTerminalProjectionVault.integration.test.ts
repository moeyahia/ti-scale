import { afterEach, describe, expect, test } from "bun:test";
import {
  resolveAutonomousRunMemoryPolicy,
  retrieveMissionBrainContext,
  type BrainLifecycleHook,
} from "../../brain-runtime";
import {
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
} from "../../domain";
import { MissionIntakeService } from "../../intake";
import {
  activeConnectedVaultBackedNodeIds,
} from "../../memory";
import { digestCanonicalJson } from "../../mcp";
import {
  autonomousContractHash,
  type AutonomousMissionRequest,
} from "../../missions";
import { ActionRepository } from "../../orchestration";
import { AttackAttemptService } from "../../run-intelligence";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_IDENTITY_ACTION_TYPE,
  AUTONOMOUS_LINUX_USER_FLAG_PROOF_ACTION_TYPE,
  AutonomousLinuxPostExploitSessionService,
  BoundedCandidateRuntimeLinuxPrivilegeAdapter,
  BoundedCandidateRuntimeLinuxSessionAdapter,
  CandidateLinuxPostExploitPlanExtension,
  CandidateLinuxPrivilegeContinuationRuntime,
  LocalVerifiedEvidenceOutcomeEvaluator,
  MissionBrainCandidateLinuxPrivilegeContext,
  autonomousSuccessCriterionId,
  type CandidateRuntimeLinuxPrivilegeRequest,
  type CandidateRuntimeLinuxPrivilegeTransport,
  type CandidateRuntimeLinuxSessionRequest,
  type CandidateRuntimeLinuxSessionTransport,
} from "../index";
import {
  LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
  LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
} from "../CandidateLinuxPrivilegeContinuation";
import {
  advanceCandidateSessionToPrivileged,
} from "../CandidateLinuxPrivilegeContinuationRuntime";
import {
  AUTONOMOUS_EXPLOIT_LOOPBACK_FIXTURE_NOW,
  createAutonomousExploitLoopbackProofSession,
  type AutonomousExploitLoopbackProofSession,
} from "../testing/AutonomousExploitLoopbackHarness";
import { completeRuntimeManifests } from
  "../../../tests/unit/domain/fixtures";

const CHAIN_NOW = "2026-07-23T23:00:00.000Z";
const OBSERVER_SPEC_ID = "observer-full-chain-vault-v1";
const POST_EXPLOIT_SPEC_ID = "post-exploit-full-chain-vault-v1";
const CANONICAL_IMPACT_EVIDENCE_ID = "evidence-full-chain-independent-impact";
const USER_FLAG_SHA256 = "a".repeat(64);
const ROOT_FLAG_SHA256 = "b".repeat(64);
const FORBIDDEN_RUNTIME_KEYS = new Set([
  "argv",
  "command",
  "content",
  "credential",
  "credentials",
  "flagContent",
  "payload",
  "secret",
  "shell",
  "stderr",
  "stdout",
  "token",
]);

const sessions: AutonomousExploitLoopbackProofSession[] = [];

afterEach(async () => {
  for (const session of sessions.splice(0)) await session.dispose();
});

function canonical(value: unknown): string {
  return JSON.stringify(value);
}

function sha256(value: unknown): string {
  return digestCanonicalJson(value, {
    maxBytes: 128 * 1_024,
    maxDepth: 24,
  }).sha256;
}

function signedReceipt<T extends Readonly<Record<string, unknown>>>(
  body: T,
  field: string,
): T & Readonly<Record<string, string>> {
  return Object.freeze({
    ...body,
    [field]: digestCanonicalJson(body, {
      maxBytes: 32 * 1_024,
      maxDepth: 12,
    }).sha256,
  });
}

function allObjectKeys(value: unknown, keys = new Set<string>()): ReadonlySet<string> {
  if (Array.isArray(value)) {
    for (const item of value) allObjectKeys(item, keys);
    return keys;
  }
  if (!value || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    keys.add(key);
    allObjectKeys(child, keys);
  }
  return keys;
}

class DeterministicFullChainTransport
implements CandidateRuntimeLinuxSessionTransport,
CandidateRuntimeLinuxPrivilegeTransport {
  readonly requests: Array<
    CandidateRuntimeLinuxSessionRequest | CandidateRuntimeLinuxPrivilegeRequest
  > = [];
  #active = false;
  #privileged = false;

  async invoke(
    request: CandidateRuntimeLinuxSessionRequest,
    signal: AbortSignal,
  ): Promise<unknown>;
  async invoke(
    request: CandidateRuntimeLinuxPrivilegeRequest,
    signal: AbortSignal,
  ): Promise<unknown>;
  async invoke(
    request:
      | CandidateRuntimeLinuxSessionRequest
      | CandidateRuntimeLinuxPrivilegeRequest,
    signal: AbortSignal,
  ): Promise<unknown> {
    if (signal.aborted) {
      throw new DOMException("Candidate transport was cancelled", "AbortError");
    }
    this.requests.push(request);
    if (request.operation === "open") {
      this.#active = true;
      return {
        accepted: true,
        sessionArtifactId: request.sessionArtifactId,
      };
    }
    if (request.operation === "observe_identity") {
      if (!this.#active) throw new Error("Identity requested before session open");
      return {
        sessionArtifactId: request.sessionArtifactId,
        principal: "fixtureuser",
        uid: 1000,
        gid: 1000,
        groups: ["fixtureuser"],
      };
    }
    if (request.operation === "prove_user_flag_hash") {
      if (!this.#active) throw new Error("User proof requested before session open");
      return {
        sessionArtifactId: request.sessionArtifactId,
        declaredPath: request.declaredPath,
        sha256: USER_FLAG_SHA256,
        byteSize: 32,
      };
    }
    if (request.operation === "close") {
      this.#active = false;
      this.#privileged = false;
      return {
        closed: true,
        sessionArtifactId: request.sessionArtifactId,
      };
    }
    if (request.operation === "privilege_escalation") {
      if (!this.#active) throw new Error("Privilege requested before session open");
      this.#privileged = true;
      return signedReceipt({
        schemaVersion: LOOPBACK_LINUX_PRIVILEGE_ACK_SCHEMA_VERSION,
        sessionArtifactId: request.sessionArtifactId,
        accepted: true,
        observedAt: CHAIN_NOW,
      }, "receiptSha256");
    }
    if (request.operation === "observe_root_identity") {
      if (!this.#privileged) {
        throw new Error("Root identity requested before privilege proof");
      }
      return signedReceipt({
        schemaVersion: LOOPBACK_LINUX_ROOT_IDENTITY_SCHEMA_VERSION,
        sessionArtifactId: request.sessionArtifactId,
        principal: "root",
        uid: 0,
        gid: 0,
        groups: ["root"],
        observedAt: CHAIN_NOW,
      }, "observationSha256");
    }
    if (request.operation === "prove_root_flag_hash") {
      if (!this.#privileged) {
        throw new Error("Root proof requested before privilege proof");
      }
      return signedReceipt({
        schemaVersion: LOOPBACK_LINUX_ROOT_FLAG_PROOF_SCHEMA_VERSION,
        sessionArtifactId: request.sessionArtifactId,
        declaredPath: request.declaredPath,
        contentSha256: ROOT_FLAG_SHA256,
        byteSize: 32,
        observedAt: CHAIN_NOW,
      }, "proofSha256");
    }
    if (!this.#active) throw new Error("Cleanup requested without an active session");
    this.#active = false;
    this.#privileged = false;
    return signedReceipt({
      schemaVersion: LOOPBACK_LINUX_CLEANUP_ACK_SCHEMA_VERSION,
      sessionArtifactId: request.sessionArtifactId,
      closed: true,
      observedAt: CHAIN_NOW,
    }, "receiptSha256");
  }
}

describe("Autonomous preseeded terminal-projection active-Vault integration", () => {
  test("projects preseeded canonical exploit, cleanup, evaluation, report, and Vault records without claiming cold-start execution proof", async () => {
    const fixture = await createAutonomousExploitLoopbackProofSession();
    sessions.push(fixture);
    fixture.refreshActiveVaultHealthProof(new Date(CHAIN_NOW));
    const database = fixture.database;
    const seeded = database.prepare(`
      SELECT mission.id AS mission_id, mission.memory_policy_json,
        run.id AS run_id, run.contract_id, run.current_plan_id,
        target.normalized_target
      FROM missions mission
      JOIN runs run ON run.mission_id = mission.id
      JOIN mission_targets target ON target.mission_id = mission.id
        AND target.disposition = 'allowed'
      ORDER BY mission.created_at, run.created_at LIMIT 1
    `).get() as {
      readonly mission_id: string;
      readonly memory_policy_json: string;
      readonly run_id: string;
      readonly contract_id: string;
      readonly current_plan_id: string;
      readonly normalized_target: string;
    };
    const originalMemoryPolicy = JSON.parse(
      seeded.memory_policy_json,
    ) as {
      readonly exactContextNodeIds: readonly string[];
      readonly allowedScopes: readonly string[];
    };

    // This is the real registry-backed intake resolver. It runs before the
    // target proof and produces the signed authority later bound to the run.
    const intakeRuntimeManifests = completeRuntimeManifests();
    const intake = new MissionIntakeService({
      readRuntimeManifests: () => ({
        ...intakeRuntimeManifests,
        providers: intakeRuntimeManifests.providers.map((provider) => ({
          ...provider,
          catalogObservedAt: CHAIN_NOW,
        })),
      }),
      clock: () => new Date(CHAIN_NOW),
    });
    const intakeBase = {
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: seeded.normalized_target }],
      templateId: "htb_web_full_path",
      environmentClassification: "htb",
      successCriteria: [
        ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
      ],
      memoryScopes: ["verified_attack_knowledge"],
      contextNodeIds: originalMemoryPolicy.exactContextNodeIds,
    } as const;
    const targetPreview = intake.resolve(intakeBase);
    const resolved = intake.resolve({
      ...intakeBase,
      destructivePolicy: "bounded_lab_only",
      boundedDestructiveTargetIds: [targetPreview.normalizedTargets[0]!.id],
    });
    expect(resolved.limitations).toEqual([]);
    expect(resolved.request.journey).toBe("autonomous");
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Autonomous intake unexpectedly resolved to Guided");
    }
    const intakeRequest = resolved.request;
    expect(intakeRequest.contract.allowedActionClasses).toEqual(
      expect.arrayContaining([
        "exploit_validation",
        "command_session_execution",
        "data_access_impact_validation",
        "privilege_escalation",
        "cleanup_restoration",
      ]),
    );

    const contractHash = autonomousContractHash(intakeRequest);
    expect(contractHash).toMatch(/^[a-f0-9]{64}$/u);
    // Persist the registry-resolved authority before any target action. The
    // reusable exploit harness already owns an immutable fixture run binding,
    // so this projection test retains that binding instead of weakening its trigger.
    database.transaction(() => {
      database.prepare(`
        UPDATE missions
        SET name = ?, objective = ?, status = 'active',
          success_criteria_json = ?, memory_policy_json = ?,
          updated_at = ?, version = version + 1
        WHERE id = ?
      `).run(
        intakeRequest.title,
        intakeRequest.objective,
        canonical(intakeRequest.successCriteria),
        canonical({
          exactContextNodeIds: intakeRequest.contract.contextNodeIds,
          allowedScopes: intakeRequest.contract.memoryScopes,
        }),
        CHAIN_NOW,
        seeded.mission_id,
      );
      database.prepare(`
        UPDATE mission_contracts
        SET authorization_json = ?,
          action_policy_json = ?, budgets_json = ?, safe_stop_json = ?,
          deliverables_json = ?, memory_scopes_json = ?
        WHERE id = ?
      `).run(
        canonical(intakeRequest.authorization),
        canonical(intakeRequest.contract),
        canonical({
          timeBudgetMinutes: intakeRequest.contract.timeBudgetMinutes,
          toolCallBudget: intakeRequest.contract.toolCallBudget,
          tokenBudget: intakeRequest.contract.tokenBudget,
          costBudget: intakeRequest.contract.costBudget,
          retryBudget: intakeRequest.contract.retryBudget,
          replanBudget: intakeRequest.contract.replanBudget,
          concurrencyLimit: intakeRequest.contract.concurrencyLimit,
          evidenceStorageBudgetBytes:
            intakeRequest.contract.evidenceStorageBudgetBytes,
          artifactStorageBudgetBytes:
            intakeRequest.contract.artifactStorageBudgetBytes,
        }),
        canonical({
          mandatory: resolved.mandatorySafeStopIds,
          optional: intakeRequest.contract.safeStopConditions,
        }),
        canonical(intakeRequest.contract.deliverables),
        canonical(intakeRequest.contract.memoryScopes),
        seeded.contract_id,
      );
    })();

    const exploitProof = await fixture.run();
    expect(exploitProof).toMatchObject({
      fixtureOnly: true,
      impact: { outcome: "success" },
      vault: { healthy: true, unresolvedWikilinkCount: 0 },
      brain: { providerTurnCount: 0, publicProviderContact: false },
    });

    database.transaction(() => {
      database.prepare(`
        UPDATE plans SET status = 'active' WHERE id = ?
      `).run(seeded.current_plan_id);
      database.prepare(`
        UPDATE runs
        SET status = 'running', progress = 0.3,
          status_reason = 'Verified exploit proof retained; materializing the signed post-exploit chain.',
          next_action_summary = 'Confirm the candidate-bound session identity.',
          ended_at = NULL, updated_at = ?, version = version + 1
        WHERE id = ?
      `).run(CHAIN_NOW, seeded.run_id);
    })();

    const brain = fixture.brain;
    const policy = () => resolveAutonomousRunMemoryPolicy({
      database,
      missionId: seeded.mission_id,
      runId: seeded.run_id,
    });
    const manualContextPackIds: string[] = [];
    const useContext = (
      hook: BrainLifecycleHook,
      explanation: string,
      stepId?: string,
      actionId?: string,
    ) => {
      const result = retrieveMissionBrainContext({
        brainContext: brain,
        hook,
        journey: "autonomous",
        missionId: seeded.mission_id,
        ...(hook === "intake" ? {} : { runId: seeded.run_id }),
        ...(stepId ? { stepId } : {}),
        ...(actionId ? { actionId } : {}),
        actorId: `system:full-chain-${hook}`,
        actorType: "system",
        query: explanation,
        queryRedacted: explanation,
        memoryPolicy: policy(),
        maximumSensitivity: "private",
        contextBudget: 3_000,
        limit: 10,
        ...(hook === "closeout" ? { terminalSafe: true } : {}),
      });
      const usedNodeIds = result.contextPack.items.map(({ nodeId }) => nodeId);
      expect(usedNodeIds.length).toBeGreaterThan(0);
      brain.recordContextUse(
        result,
        usedNodeIds,
        `The deterministic ${hook} boundary used the exact signed, active-Vault-backed attack context.`,
        "No selected exact-memory item was ignored.",
      );
      const vaultBacked = activeConnectedVaultBackedNodeIds(
        database,
        result.contextPack.id,
      );
      expect(usedNodeIds.every((nodeId) => vaultBacked.has(nodeId))).toBe(true);
      manualContextPackIds.push(result.contextPack.id);
      return result;
    };

    useContext(
      "intake",
      "Bind the resolved Autonomous contract to the exact confirmed attack-memory selection.",
    );
    useContext(
      "planning",
      "Extend the verified exploit proof with the bounded user, root, and cleanup proof sequence.",
    );

    const exploitAction = database.prepare(`
      SELECT id, step_id FROM actions
      WHERE run_id = ? AND action_type =
        'ti-scale:autonomous-script-exploit-validation'
      ORDER BY created_at, id LIMIT 1
    `).get(seeded.run_id) as {
      readonly id: string;
      readonly step_id: string;
    };
    const exploitAttempt = database.prepare(`
      SELECT id, target_asset_id FROM attack_attempts
      WHERE run_id = ? AND step_id = ? AND status = 'succeeded'
      ORDER BY ended_at, id LIMIT 1
    `).get(seeded.run_id, exploitAction.step_id) as {
      readonly id: string;
      readonly target_asset_id: string;
    };
    const exploitKnowledge = database.prepare(`
      SELECT procedure_node_id, product_node_ids_json,
        version_node_ids_json, stack_node_ids_json,
        prerequisite_node_ids_json, observed_state_node_ids_json,
        context_pack_id
      FROM attack_attempt_knowledge_contexts
      WHERE attack_attempt_id = ?
    `).get(exploitAttempt.id) as {
      readonly procedure_node_id: string;
      readonly product_node_ids_json: string;
      readonly version_node_ids_json: string;
      readonly stack_node_ids_json: string;
      readonly prerequisite_node_ids_json: string;
      readonly observed_state_node_ids_json: string;
      readonly context_pack_id: string;
    };
    useContext(
      "attack_attempt",
      "Retain the exact procedure, product, and version used by the independently verified exploit attempt.",
      exploitAction.step_id,
      exploitAction.id,
    );

    const canonicalImpactProvenance = {
      schemaVersion: "ti-scale.exploit-outcome-observation.v1",
      matched: true,
      independentObserver: true,
      sourceEvidenceId: exploitProof.impact.evidenceId,
      sourceAttackAttemptId: exploitAttempt.id,
      successCriterionReferences: [{
        schemaVersion: "ti-scale.success-criterion-reference.v1",
        criterionId: autonomousSuccessCriterionId(
          AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA[0],
        ),
        outcome: "achieved",
      }],
    };
    database.transaction(() => {
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, 'local:independent-http-outcome-observer',
          ?, ?, 'exploit_validation_result', ?, ?, 1, 'internal', 'verified',
          'An independent local observer correlated the real disposable target response with the exact succeeded exploit attempt.',
          NULL, NULL, 'system:full-chain-impact-observer', ?)
      `).run(
        CANONICAL_IMPACT_EVIDENCE_ID,
        seeded.mission_id,
        seeded.run_id,
        exploitAction.step_id,
        exploitAction.id,
        CHAIN_NOW,
        seeded.normalized_target,
        sha256(canonicalImpactProvenance),
        canonical(canonicalImpactProvenance),
        CHAIN_NOW,
      );
      database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES
          ('chain-full-impact-acquired', ?, 'acquired',
            'system:full-chain-impact-observer',
            '{"independentObserver":true}', ?),
          ('chain-full-impact-verified', ?, 'verified',
            'system:full-chain-impact-observer',
            '{"matched":true,"rawOutputRetained":false}', ?)
      `).run(
        CANONICAL_IMPACT_EVIDENCE_ID,
        CHAIN_NOW,
        CANONICAL_IMPACT_EVIDENCE_ID,
        CHAIN_NOW,
      );
      database.prepare(`
        INSERT INTO attack_attempt_evidence (
          attack_attempt_id, evidence_id, relationship, created_at
        ) VALUES (?, ?, 'outcome', ?)
      `).run(
        exploitAttempt.id,
        CANONICAL_IMPACT_EVIDENCE_ID,
        CHAIN_NOW,
      );
      database.prepare(`
        INSERT INTO exploit_outcome_observer_specs (
          id, script_artifact_id, script_content_hash, cve_id,
          observer_type, request_json, assertion_json, spec_hash,
          status, created_by, created_at
        ) VALUES (?, ?, ?, ?, 'http_response_assertion',
          '{"method":"GET","fixtureOnly":true}',
          '{"matched":true,"fixtureOnly":true}', ?,
          'active', 'operator:full-chain-gate', ?)
      `).run(
        OBSERVER_SPEC_ID,
        exploitProof.scriptArtifact.id,
        exploitProof.scriptArtifact.contentHash,
        exploitProof.reconnaissance.cveId,
        sha256({
          observer: OBSERVER_SPEC_ID,
          scriptContentHash: exploitProof.scriptArtifact.contentHash,
        }),
        CHAIN_NOW,
      );
      database.prepare(`
        INSERT INTO candidate_linux_post_exploit_specs (
          id, exploit_outcome_observer_spec_id, script_artifact_id,
          transport_type, transport_binding_id, transport_origin,
          open_path, identity_path, user_flag_proof_path, privilege_path,
          root_identity_path, root_flag_proof_path, cleanup_path,
          expected_principal, expected_uid, declared_user_flag_path,
          declared_root_flag_path, spec_hash, status, created_by, created_at
        ) VALUES (?, ?, ?, 'candidate_runtime_session_v1',
          'fixture.full-chain-typed-session.v1', NULL,
          '/ti-scale/session/open', '/ti-scale/session/identity',
          '/ti-scale/session/user-flag-proof',
          '/ti-scale/session/privilege-escalation',
          '/ti-scale/session/root-identity',
          '/ti-scale/session/root-flag-proof',
          '/ti-scale/session/cleanup',
          'fixtureuser', 1000, '/home/fixtureuser/user.txt',
          '/root/root.txt', ?, 'active', 'operator:full-chain-gate', ?)
      `).run(
        POST_EXPLOIT_SPEC_ID,
        OBSERVER_SPEC_ID,
        exploitProof.scriptArtifact.id,
        sha256({
          spec: POST_EXPLOIT_SPEC_ID,
          binding: "fixture.full-chain-typed-session.v1",
          scriptContentHash: exploitProof.scriptArtifact.contentHash,
        }),
        CHAIN_NOW,
      );
    })();

    // The original exploit harness records human-readable prerequisites. The
    // post-exploit authority requires a stable ScriptArtifact prerequisite, so
    // retain a second immutable attempt classification over the same real
    // execution/evidence instead of rewriting the historical attempt.
    const attempts = new AttackAttemptService(
      database,
      () => new Date(CHAIN_NOW),
    );
    let candidateAttempt = attempts.create({
      missionId: seeded.mission_id,
      runId: seeded.run_id,
      planId: seeded.current_plan_id,
      stepId: exploitAction.step_id,
      targetAssetId: exploitAttempt.target_asset_id,
      objective:
        "Bind the actual independently verified exploit execution to the reviewed post-exploit candidate.",
      techniqueName: "Candidate-bound disposable exploit validation",
      actionClass: "exploit_validation",
      prerequisites: [exploitProof.scriptArtifact.id],
      normalizedParameters: {
        scriptArtifactId: exploitProof.scriptArtifact.id,
        scriptContentHash: exploitProof.scriptArtifact.contentHash,
        sourceAttackAttemptId: exploitAttempt.id,
      },
      assignedAgentId: "agent-loopback-exploit",
      reviewedKnowledgeBinding: {
        procedureNodeId: exploitKnowledge.procedure_node_id,
        productNodeIds: JSON.parse(
          exploitKnowledge.product_node_ids_json,
        ) as string[],
        versionNodeIds: JSON.parse(
          exploitKnowledge.version_node_ids_json,
        ) as string[],
        stackNodeIds: JSON.parse(
          exploitKnowledge.stack_node_ids_json,
        ) as string[],
        prerequisiteNodeIds: JSON.parse(
          exploitKnowledge.prerequisite_node_ids_json,
        ) as string[],
        observedStateNodeIds: JSON.parse(
          exploitKnowledge.observed_state_node_ids_json,
        ) as string[],
        normalizedParameters: {
          scriptSha256: exploitProof.scriptArtifact.contentHash,
        },
        load: 1,
        concurrency: 1,
      },
    });
    database.prepare(`
      UPDATE attack_attempt_knowledge_contexts
      SET context_pack_id = ?, updated_at = ?
      WHERE attack_attempt_id = ?
    `).run(
      exploitKnowledge.context_pack_id,
      CHAIN_NOW,
      candidateAttempt.id,
    );
    candidateAttempt = attempts.transition({
      attemptId: candidateAttempt.id,
      expectedVersion: candidateAttempt.version,
      status: "ready",
    });
    candidateAttempt = attempts.transition({
      attemptId: candidateAttempt.id,
      expectedVersion: candidateAttempt.version,
      status: "running",
    });
    attempts.complete({
      attemptId: candidateAttempt.id,
      expectedVersion: candidateAttempt.version,
      outcome: "succeeded",
      outcomeSummary:
        "The candidate is bound to the actual independently observed disposable exploit result.",
      evidence: [{
        evidenceId: CANONICAL_IMPACT_EVIDENCE_ID,
        relationship: "outcome",
      }],
    });

    const extension = new CandidateLinuxPostExploitPlanExtension({
      database,
      agentId: "agent-loopback-exploit",
    }).prepare({
      missionId: seeded.mission_id,
      runId: seeded.run_id,
      exactTarget: seeded.normalized_target,
      materialization: {
        materializedScriptArtifactId: exploitProof.scriptArtifact.id,
      } as never,
      exploitStep: {} as never,
    });
    expect(extension).not.toBeNull();
    if (!extension) throw new Error("Post-exploit planner returned no extension");
    expect(extension.steps.map(({ action }) => action.actionType)).toEqual([
      AUTONOMOUS_LINUX_SESSION_IDENTITY_ACTION_TYPE,
      AUTONOMOUS_LINUX_USER_FLAG_PROOF_ACTION_TYPE,
      AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
      AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
      AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
    ]);

    const stepIds = extension.steps.map((_, index) =>
      `step-full-chain-${index + 1}`);
    const dependencies = stepIds.map((_, index) =>
      index === 0 ? [exploitAction.step_id] : [stepIds[index - 1]!]);
    const insertStep = database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        success_criteria_json, dependencies_json, action_class, risk_class,
        assigned_agent_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
    `);
    database.transaction(() => {
      extension.steps.forEach((step, index) => {
        insertStep.run(
          stepIds[index]!,
          seeded.current_plan_id,
          seeded.run_id,
          index + 2,
          step.phase,
          step.title,
          step.objective,
          canonical(step.successCriteria),
          canonical(dependencies[index]),
          step.action.actionClass,
          step.riskClass,
          step.assignedAgentId,
          CHAIN_NOW,
          CHAIN_NOW,
        );
      });
      database.prepare(`
        UPDATE runs SET current_step_id = ?,
          next_action_summary = ?, updated_at = ?, version = version + 1
        WHERE id = ?
      `).run(
        stepIds[0],
        extension.steps[0]!.action.intentSummary,
        CHAIN_NOW,
        seeded.run_id,
      );
    })();
    expect(
      database.prepare(`
        SELECT dependencies_json FROM plan_steps
        WHERE id IN (?, ?, ?, ?, ?) ORDER BY ordinal
      `).all(...stepIds).map((row) =>
        JSON.parse((row as { dependencies_json: string }).dependencies_json)),
    ).toEqual(dependencies);

    useContext(
      "phase_transition",
      "Move from independently verified exploit impact into the candidate-bound post-exploit proof sequence.",
    );
    const transport = new DeterministicFullChainTransport();
    const sessionRuntime = new AutonomousLinuxPostExploitSessionService({
      database,
      brainContext: brain,
      adapter: new BoundedCandidateRuntimeLinuxSessionAdapter(transport),
      assertControlPlaneAuthority: () => ({
        runId: seeded.run_id,
        controlPlane: "ti_scale",
      }),
      agentId: "agent-loopback-exploit",
      now: () => new Date(CHAIN_NOW),
    });
    const privilegeRuntime = new CandidateLinuxPrivilegeContinuationRuntime({
      database,
      adapter: new BoundedCandidateRuntimeLinuxPrivilegeAdapter(transport),
      brain: new MissionBrainCandidateLinuxPrivilegeContext({
        database,
        brainContext: brain,
      }),
      assertControlPlaneAuthority: () => ({
        runId: seeded.run_id,
        controlPlane: "ti_scale",
        leaseOwner: "fixture-full-chain-runtime",
        acquiredAt: CHAIN_NOW,
        heartbeatAt: CHAIN_NOW,
        expiresAt: "2026-07-24T00:00:00.000Z",
        version: 1,
      }),
      leaseOwner: "fixture-full-chain-session-runtime",
      randomToken: () => "fixture-full-chain-fenced-lease-token",
      now: () => new Date(CHAIN_NOW),
    });
    const actions = new ActionRepository(database);
    const completedActionIds = [exploitAction.id];
    const actionContextPackIds: string[] = [];
    for (const [index, planned] of extension.steps.entries()) {
      const stepId = stepIds[index]!;
      database.prepare(`
        UPDATE plan_steps SET status = 'running', started_at = ?,
          updated_at = ? WHERE id = ?
      `).run(CHAIN_NOW, CHAIN_NOW, stepId);
      database.prepare(`
        UPDATE runs SET current_step_id = ?, next_action_summary = ?,
          updated_at = ?, version = version + 1 WHERE id = ?
      `).run(stepId, planned.action.intentSummary, CHAIN_NOW, seeded.run_id);
      const action = actions.create({
        intent: {
          missionId: seeded.mission_id,
          runId: seeded.run_id,
          stepId,
          planVersion: 1,
          actionType: planned.action.actionType,
          actionClass: planned.action.actionClass,
          arguments: planned.action.arguments,
          target: planned.action.target,
          intentSummary: planned.action.intentSummary,
          kind: planned.action.kind,
          idempotent: planned.action.idempotent,
          destructive: planned.action.destructive,
        },
        fingerprint: sha256(planned.action.arguments),
        contractId: seeded.contract_id,
        now: CHAIN_NOW,
      });
      useContext(
        "assignment_acceptance",
        `Accept only the represented ${planned.phase} assignment for the exact candidate and signed plan.`,
        stepId,
        action.id,
      );
      if (index === 2) {
        const beforeCompetingWrite = database.prepare(`
          SELECT id, version FROM session_artifacts WHERE run_id = ?
        `).get(seeded.run_id) as {
          readonly id: string;
          readonly version: number;
        };
        database.prepare(`
          UPDATE session_artifacts
          SET updated_at = ?, version = version + 1
          WHERE id = ? AND status = 'active' AND access_level = 'user'
        `).run(CHAIN_NOW, beforeCompetingWrite.id);
        expect(() => advanceCandidateSessionToPrivileged({
          database,
          sessionArtifactId: beforeCompetingWrite.id,
          expectedVersion: beforeCompetingWrite.version,
          updatedAt: CHAIN_NOW,
        })).toThrow(
          expect.objectContaining({
            code: "autonomous_linux_root_identity_state_conflict",
          }),
        );
        expect(database.prepare(`
          SELECT version, status, access_level
          FROM session_artifacts WHERE id = ?
        `).get(beforeCompetingWrite.id)).toEqual({
          version: beforeCompetingWrite.version + 1,
          status: "active",
          access_level: "user",
        });
      }
      const result = index < 2
        ? await sessionRuntime.execute(action, new AbortController().signal)
        : await privilegeRuntime.execute(action, new AbortController().signal);
      actionContextPackIds.push(result.contextPackId);
      actions.complete({
        actionId: action.id,
        success: true,
        summary: result.summary,
        progressSignature: sha256({
          actionId: action.id,
          evidenceIds: "evidenceIds" in result
            ? result.evidenceIds
            : [result.evidenceId],
        }),
        now: CHAIN_NOW,
      });
      database.prepare(`
        UPDATE plan_steps SET status = 'completed', ended_at = ?,
          updated_at = ? WHERE id = ?
      `).run(CHAIN_NOW, CHAIN_NOW, stepId);
      completedActionIds.push(action.id);
    }

    expect(transport.requests.map(({ operation }) => operation)).toEqual([
      "open",
      "observe_identity",
      "prove_user_flag_hash",
      "privilege_escalation",
      "observe_root_identity",
      "prove_root_flag_hash",
      "cleanup",
    ]);
    expect(
      [...allObjectKeys(transport.requests)]
        .filter((key) => FORBIDDEN_RUNTIME_KEYS.has(key)),
    ).toEqual([]);
    const storedActionArguments = database.prepare(`
      SELECT normalized_arguments_json FROM actions
      WHERE id IN (${completedActionIds.slice(1).map(() => "?").join(",")})
      ORDER BY created_at, id
    `).all(...completedActionIds.slice(1)) as Array<{
      readonly normalized_arguments_json: string;
    }>;
    expect(
      [...allObjectKeys(storedActionArguments.map(({ normalized_arguments_json }) =>
        JSON.parse(normalized_arguments_json)))]
        .filter((key) => FORBIDDEN_RUNTIME_KEYS.has(key)),
    ).toEqual([]);

    const evaluationContext = useContext(
      "evaluation",
      "Evaluate the six terminal criteria only from canonical verified evidence and durable typed proof records.",
    );
    const evaluation = await new LocalVerifiedEvidenceOutcomeEvaluator(
      database,
    ).evaluate({
      mission: {
        id: seeded.mission_id,
        createdBy: "operator:loopback-proof",
        name: intakeRequest.title,
        objective: intakeRequest.objective,
        journey: "autonomous",
        engagementId: null,
        authorizationStatus: "verified",
        allowedTargets: [...intakeRequest.authorization.allowedTargets],
        prohibitedTargets: [...intakeRequest.authorization.prohibitedTargets],
        successCriteria: [...intakeRequest.successCriteria],
        memoryPolicy: policy(),
      },
      run: {
        id: seeded.run_id,
        missionId: seeded.mission_id,
        journey: "autonomous",
        state: "running",
        replanCount: 0,
        currentPlanVersion: 1,
        previousStrategySummary: extension.strategySummary,
        stateReason: "All six terminal proof criteria are ready for local evaluation.",
      },
      planId: seeded.current_plan_id,
      completedActionIds,
      brainContext: brain.providerContext(evaluationContext),
    }, new AbortController().signal);
    expect(evaluation.success).toBe(true);
    expect(evaluation.criteria).toHaveLength(6);
    expect(evaluation.criteria.every(({ outcome }) =>
      outcome === "achieved")).toBe(true);

    useContext(
      "reporting",
      "Prepare the terminal completion record using verified evidence references and the signed reporting preference.",
    );
    useContext(
      "lesson_proposal",
      "Review the completed chain for evidence-linked reusable lessons without self-approving any change.",
    );
    database.transaction(() => {
      database.prepare(`
        UPDATE run_evaluations
        SET scores_json = ?, metrics_json = ?,
          retrospective =
            'The preseeded terminal projection contains all six canonical criteria with active-Vault context and no provider contact; this fixture does not prove cold-start execution.',
          evidence_coverage = 1,
          created_by = 'local:verified-evidence-evaluator',
          created_at = ?
        WHERE run_id = ?
      `).run(
        canonical({
          objectiveCompletion: 1,
          evidenceQuality: 1,
          policyCompliance: 1,
          journeyAdherence: 1,
        }),
        canonical({
          criteriaAchieved: 6,
          criteriaTotal: 6,
          providerTurns: 0,
          retries: 0,
          postExploitActionsSucceeded: 5,
        }),
        CHAIN_NOW,
        seeded.run_id,
      );
      database.prepare(`
        UPDATE plans SET status = 'completed' WHERE id = ?
      `).run(seeded.current_plan_id);
      database.prepare(`
        UPDATE runs
        SET status = 'completed', progress = 1,
          status_reason =
            'Completed autonomously: exploit, user, root, and cleanup proofs are verified.',
          next_action_summary =
            'Review the canonical evidence and synchronized Vault context receipts.',
          current_step_id = ?, ended_at = ?, updated_at = ?,
          version = version + 1
        WHERE id = ?
      `).run(
        stepIds.at(-1),
        CHAIN_NOW,
        CHAIN_NOW,
        seeded.run_id,
      );
      database.prepare(`
        UPDATE missions SET status = 'completed', updated_at = ?,
          version = version + 1 WHERE id = ?
      `).run(CHAIN_NOW, seeded.mission_id);
    })();
    useContext(
      "closeout",
      "Close the completed mission after preserving evidence links, released leases, and active Vault context receipts.",
    );

    const finalState = database.prepare(`
      SELECT mission.status AS mission_status, run.status AS run_status,
        run.progress, plan.status AS plan_status,
        session.status AS session_status, session.access_level,
        (SELECT COUNT(*) FROM session_artifact_leases lease
          WHERE lease.session_artifact_id = session.id
            AND lease.released_at IS NULL) AS active_leases,
        (SELECT COUNT(*) FROM provider_turns provider
          WHERE provider.run_id = run.id) AS provider_turns,
        (SELECT COUNT(*) FROM evidence evidence
          WHERE evidence.run_id = run.id
            AND evidence.evidence_type = 'command_output') AS command_evidence,
        (SELECT COUNT(*) FROM session_flag_proofs proof
          WHERE proof.session_artifact_id = session.id) AS flag_proofs
      FROM missions mission
      JOIN runs run ON run.mission_id = mission.id
      JOIN plans plan ON plan.id = run.current_plan_id
      JOIN session_artifacts session ON session.run_id = run.id
      WHERE run.id = ?
    `).get(seeded.run_id);
    expect(finalState).toEqual({
      mission_status: "completed",
      run_status: "completed",
      progress: 1,
      plan_status: "completed",
      session_status: "closed",
      access_level: "root",
      active_leases: 0,
      provider_turns: 0,
      command_evidence: 0,
      flag_proofs: 2,
    });

    const retainedFlagEvidence = database.prepare(`
      SELECT proof_kind, declared_path, content_sha256, byte_size,
        evidence.extracted_text, evidence.provenance_json
      FROM session_flag_proofs proof
      JOIN evidence ON evidence.id = proof.evidence_id
      ORDER BY proof_kind
    `).all() as Array<{
      readonly proof_kind: string;
      readonly declared_path: string;
      readonly content_sha256: string;
      readonly byte_size: number;
      readonly extracted_text: string | null;
      readonly provenance_json: string;
    }>;
    expect(retainedFlagEvidence).toHaveLength(2);
    expect(retainedFlagEvidence.every((proof) => {
      const provenance = JSON.parse(proof.provenance_json) as Record<string, unknown>;
      return /^[a-f0-9]{64}$/u.test(proof.content_sha256)
        && proof.byte_size === 32
        && proof.extracted_text === null
        && provenance.rawContentRetained === false
        && !Object.hasOwn(provenance, "contentRetained");
    })).toBe(true);

    const coverage = brain.coverage({
      missionId: seeded.mission_id,
      runId: seeded.run_id,
    });
    expect(coverage.coveredHooks).toEqual(expect.arrayContaining([
      "intake",
      "planning",
      "assignment_acceptance",
      "tool_selection",
      "attack_attempt",
      "phase_transition",
      "evaluation",
      "reporting",
      "lesson_proposal",
      "closeout",
    ]));
    const everyUsedPack = database.prepare(`
      SELECT DISTINCT context_pack_id
      FROM memory_context_items WHERE used = 1
      ORDER BY context_pack_id
    `).all() as Array<{ readonly context_pack_id: string }>;
    expect(everyUsedPack.length).toBeGreaterThanOrEqual(
      new Set([...manualContextPackIds, ...actionContextPackIds]).size,
    );
    for (const { context_pack_id } of everyUsedPack) {
      const used = database.prepare(`
        SELECT node_id FROM memory_context_items
        WHERE context_pack_id = ? AND used = 1 ORDER BY node_id
      `).all(context_pack_id) as Array<{ readonly node_id: string }>;
      const vaultBacked = activeConnectedVaultBackedNodeIds(
        database,
        context_pack_id,
      );
      expect(used.length).toBeGreaterThan(0);
      expect(used.every(({ node_id }) => vaultBacked.has(node_id))).toBe(true);
    }
    expect(AUTONOMOUS_EXPLOIT_LOOPBACK_FIXTURE_NOW < CHAIN_NOW).toBe(true);
  }, 30_000);
});
