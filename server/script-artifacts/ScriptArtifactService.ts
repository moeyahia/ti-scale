import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import { canonicalJson } from "../run-intelligence/serialization";
import { ScriptArtifactRepository } from "./ScriptArtifactRepository";
import type { ScriptSourceStore } from "./ScriptSourceStore";
import type {
  CreateScriptArtifactInput,
  CreateScriptVersionInput,
  ScriptArtifactActor,
  ScriptArtifactDetail,
  ScriptArtifactListFilter,
  ScriptArtifactSummary,
  ScriptLanguage,
  ScriptValidationDocumentation,
  ScriptVersionDiff,
} from "./types";
import { ScriptArtifactError } from "./types";
import {
  safeScriptName,
  scriptContentHash,
  validateCreateScriptArtifactInput,
  validateCreateScriptVersionInput,
} from "./validation";

interface MissionRow {
  readonly journey: "autonomous" | "guided";
  readonly control_plane: "legacy" | "ti_scale";
}

interface RunRow {
  readonly mission_id: string;
  readonly journey: "autonomous" | "guided";
  readonly mission_journey: "autonomous" | "guided";
  readonly control_plane: "legacy" | "ti_scale";
}

interface PlanRow {
  readonly mission_id: string;
  readonly run_id: string;
}

interface StepRow extends PlanRow {
  readonly plan_id: string;
}

interface TargetRow {
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly scope_status: string;
}

interface AttemptRow extends PlanRow {
  readonly plan_id: string | null;
  readonly step_id: string | null;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
}

interface ArtifactScopeRow {
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly artifact_type: string;
}

const TEST_ARTIFACT_TYPES = new Set(["script_test_result", "generated_script_test", "test_result"]);

const MEDIA_TYPES: Readonly<Record<ScriptLanguage, string>> = {
  bash: "text/x-shellscript",
  c: "text/x-c",
  cpp: "text/x-c++src",
  csharp: "text/x-csharp",
  go: "text/x-go",
  java: "text/x-java-source",
  javascript: "text/javascript",
  lua: "text/x-lua",
  perl: "text/x-perl",
  powershell: "text/x-powershell",
  python: "text/x-python",
  ruby: "text/x-ruby",
  rust: "text/x-rust",
  sql: "application/sql",
  typescript: "text/typescript",
};

function conflict(code: string, message: string, remediation: string): ScriptArtifactError {
  return new ScriptArtifactError(code, message, "scope_conflict", 409, remediation);
}

function comparable(value: unknown): string {
  return canonicalJson(value as never);
}

function changedFields(previous: ScriptArtifactSummary, next: CreateScriptVersionInput): readonly string[] {
  const fields: Array<readonly [string, unknown, unknown]> = [
    ["language", previous.language, next.language],
    ["laymanExplanation", previous.laymanExplanation, next.laymanExplanation],
    ["technicalPurpose", previous.technicalPurpose, next.technicalPurpose],
    ["inputs", previous.inputs, next.inputs],
    ["expectedOutputs", previous.expectedOutputs, next.expectedOutputs],
    ["prerequisites", previous.requirements.prerequisites, next.prerequisites],
    ["dependencies", previous.requirements.dependencies, next.dependencies],
    ["touches", previous.touches, next.touches],
    ["sideEffects", previous.risk.sideEffects, next.sideEffects],
    ["riskClass", previous.risk.riskClass, next.riskClass],
    ["reversibility", previous.risk.reversibility, next.reversibility],
    ["cleanupNotes", previous.cleanupNotes, next.cleanupNotes],
    ["secretsHandling", previous.secretsHandling, next.secretsHandling],
    ["evidenceExpectations", previous.evidenceExpectations, next.evidenceExpectations],
    ["validation", previous.validation, next.validation],
    ["provenance", {
      origin: previous.provenance.origin,
      explanation: previous.provenance.explanation,
      sourceRefs: previous.provenance.sourceRefs,
      ...(previous.provenance.authorAgentId ? { authorAgentId: previous.provenance.authorAgentId } : {}),
    }, next.provenance],
  ];
  return fields.flatMap(([name, before, after]) => comparable(before) === comparable(after) ? [] : [name]);
}

function sourceDiff(
  previous: ScriptArtifactSummary | undefined,
  previousSource: string | undefined,
  source: string,
  contentHash: string,
  changeSummary: string,
  metadataChanges: readonly string[],
): ScriptVersionDiff {
  const before = previousSource?.split("\n") ?? [];
  const after = source.split("\n");
  let prefix = 0;
  while (prefix < before.length && prefix < after.length && before[prefix] === after[prefix]) prefix += 1;
  let suffix = 0;
  while (
    suffix < before.length - prefix
    && suffix < after.length - prefix
    && before[before.length - suffix - 1] === after[after.length - suffix - 1]
  ) suffix += 1;
  const sourceChanged = !previous || previous.contentHash !== contentHash;
  return {
    ...(previous ? { previousScriptArtifactId: previous.id, fromVersion: previous.version, previousContentHash: previous.contentHash } : {}),
    toVersion: previous ? previous.version + 1 : 1,
    contentHash,
    sourceChanged,
    changedFields: [...(sourceChanged ? ["source"] : []), ...metadataChanges],
    commonPrefixLines: prefix,
    commonSuffixLines: suffix,
    removedLineCount: Math.max(0, before.length - prefix - suffix),
    addedLineCount: Math.max(0, after.length - prefix - suffix),
    changeSummary,
  };
}

/**
 * Canonical ScriptArtifact service. It persists documented source versions,
 * audit, and semantic events only; it deliberately exposes no execution API.
 */
export class ScriptArtifactService {
  readonly repository: ScriptArtifactRepository;
  private readonly audit: AuditTrailWriter;
  private readonly events: EventRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly sourceStore: ScriptSourceStore,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.repository = new ScriptArtifactRepository(database);
    this.audit = new AuditTrailWriter(database);
    this.events = new EventRepository(database);
  }

  get(id: string): ScriptArtifactDetail {
    const record = this.repository.get(id);
    const source = this.sourceStore.read(record.storageUri, record.contentHash);
    if (Buffer.byteLength(source, "utf8") !== record.byteSize) {
      throw new ScriptArtifactError("script_source_integrity_failure", "Canonical script source byte size does not match its artifact record", "data_integrity", 500);
    }
    return { ...record, source };
  }

  list(filter: ScriptArtifactListFilter): readonly ScriptArtifactSummary[] {
    this.assertMission(filter.missionId, false);
    if (filter.runId) this.assertRun(filter.missionId, filter.runId, false);
    if (filter.planId) this.assertPlan(filter.missionId, filter.runId, filter.planId);
    if (filter.stepId) this.assertStep(filter.missionId, filter.runId, filter.planId, filter.stepId);
    if (filter.targetNodeId) this.assertTarget(filter.missionId, filter.runId, filter.targetNodeId, false);
    return this.repository.list({ ...filter, limit: Math.min(Math.max(filter.limit ?? 100, 1), 100) });
  }

  create(raw: CreateScriptArtifactInput, actor: ScriptArtifactActor): ScriptArtifactDetail {
    const input = validateCreateScriptArtifactInput(raw);
    return inImmediateTransaction(this.database, () => {
      const mission = this.validateScope(input, true);
      this.validateDocumentation(input.validation, input.secretsHandling, input.inputs, input.provenance, input.missionId, input.runId, input.stepId, actor);
      if (this.repository.latest(input.missionId, input.name)) {
        throw new ScriptArtifactError(
          "script_artifact_name_conflict",
          "A version chain already exists for this script name",
          "state_conflict",
          409,
          "Create a new immutable version from the latest script record or choose a distinct safe relative name.",
        );
      }
      const contentHash = scriptContentHash(input.source);
      const stored = this.sourceStore.put(contentHash, input.source);
      const ids = this.repository.createIds();
      const now = this.clock().toISOString();
      const diff = sourceDiff(undefined, undefined, input.source, contentHash, "Initial documented script version", [
        "language", "laymanExplanation", "technicalPurpose", "inputs", "expectedOutputs",
        "prerequisites", "dependencies", "touches", "sideEffects", "riskClass", "reversibility",
        "cleanupNotes", "secretsHandling", "evidenceExpectations", "validation", "provenance",
      ]);
      const result = this.repository.insert({
        id: ids.scriptArtifactId,
        artifactId: ids.artifactId,
        ...input,
        journey: mission.journey,
        version: 1,
        contentHash,
        byteSize: stored.byteSize,
        mediaType: MEDIA_TYPES[input.language],
        storageUri: stored.storageUri,
        risk: { riskClass: input.riskClass, sideEffects: input.sideEffects, reversibility: input.reversibility },
        actor,
        diff,
        createdAt: now,
      });
      this.recordMutation(result, actor, "script_artifact.created", "Created an immutable documented script source version", now);
      return { ...result, source: input.source };
    });
  }

  createVersion(raw: CreateScriptVersionInput, actor: ScriptArtifactActor): ScriptArtifactDetail {
    const input = validateCreateScriptVersionInput(raw);
    return inImmediateTransaction(this.database, () => {
      const previous = this.repository.get(input.scriptArtifactId);
      const latest = this.repository.latest(previous.missionId, previous.name);
      if (!latest || latest.id !== previous.id || latest.version !== input.expectedVersion) {
        throw new ScriptArtifactError(
          "script_artifact_version_conflict",
          "Script version changed after it was loaded",
          "state_conflict",
          409,
          "Reload the latest immutable script version, review its hash and diff, then retry.",
        );
      }
      safeScriptName(previous.name, input.language);
      const mission = this.validateScope(previous, true);
      if (input.provenance.origin !== "modified") {
        throw new ScriptArtifactError("invalid_script_version_provenance", "A new version must record modified provenance");
      }
      this.validateDocumentation(input.validation, input.secretsHandling, input.inputs, input.provenance, previous.missionId, previous.runId, previous.stepId, actor);
      const previousSource = this.sourceStore.read(previous.storageUri, previous.contentHash);
      const contentHash = scriptContentHash(input.source);
      const metadataChanges = changedFields(previous, input);
      if (contentHash === previous.contentHash && metadataChanges.length === 0) {
        throw new ScriptArtifactError(
          "empty_script_version_change",
          "A new immutable script version requires a source or documentation change",
          "state_conflict",
          409,
          "Describe and submit a material source, validation, risk, or provenance change.",
        );
      }
      const stored = this.sourceStore.put(contentHash, input.source);
      const ids = this.repository.createIds();
      const now = this.clock().toISOString();
      const diff = sourceDiff(previous, previousSource, input.source, contentHash, input.changeSummary, metadataChanges);
      const result = this.repository.insert({
        id: ids.scriptArtifactId,
        artifactId: ids.artifactId,
        missionId: previous.missionId,
        ...(previous.runId ? { runId: previous.runId } : {}),
        ...(previous.planId ? { planId: previous.planId } : {}),
        ...(previous.stepId ? { stepId: previous.stepId } : {}),
        ...(previous.attackAttemptId ? { attackAttemptId: previous.attackAttemptId } : {}),
        ...(previous.targetNodeId ? { targetNodeId: previous.targetNodeId } : {}),
        name: previous.name,
        journey: mission.journey,
        language: input.language,
        version: previous.version + 1,
        contentHash,
        byteSize: stored.byteSize,
        mediaType: MEDIA_TYPES[input.language],
        storageUri: stored.storageUri,
        sensitivity: input.sensitivity,
        laymanExplanation: input.laymanExplanation,
        technicalPurpose: input.technicalPurpose,
        inputs: input.inputs,
        expectedOutputs: input.expectedOutputs,
        prerequisites: input.prerequisites,
        dependencies: input.dependencies,
        touches: input.touches,
        risk: { riskClass: input.riskClass, sideEffects: input.sideEffects, reversibility: input.reversibility },
        cleanupNotes: input.cleanupNotes,
        secretsHandling: input.secretsHandling,
        evidenceExpectations: input.evidenceExpectations,
        validation: input.validation,
        provenance: input.provenance,
        actor,
        diff,
        createdAt: now,
      });
      this.recordMutation(result, actor, "script_artifact.version_created", input.changeSummary, now);
      return { ...result, source: input.source };
    });
  }

  private validateScope(
    input: Pick<ScriptArtifactSummary, "missionId" | "runId" | "planId" | "stepId" | "attackAttemptId" | "targetNodeId">,
    mutable: boolean,
  ): MissionRow {
    const mission = this.assertMission(input.missionId, mutable);
    if (input.runId) this.assertRun(input.missionId, input.runId, mutable);
    if (!input.runId && (input.planId || input.stepId || input.attackAttemptId)) {
      throw conflict("script_run_scope_required", "Plan, step, and attack-attempt links require a canonical run", "Select the run that owns the requested plan context.");
    }
    if (input.planId) this.assertPlan(input.missionId, input.runId, input.planId);
    if (input.stepId) {
      if (!input.planId) throw conflict("script_plan_scope_required", "A linked script step requires its canonical plan", "Select the plan that owns the step.");
      this.assertStep(input.missionId, input.runId, input.planId, input.stepId);
    }
    if (input.targetNodeId) this.assertTarget(input.missionId, input.runId, input.targetNodeId, mutable);
    if (input.attackAttemptId) this.assertAttempt(input);
    return mission;
  }

  private validateDocumentation(
    validation: ScriptValidationDocumentation,
    secretsHandling: string,
    inputs: readonly { readonly sensitivity: string }[],
    provenance: { readonly origin: string; readonly sourceRefs: readonly string[]; readonly authorAgentId?: string },
    missionId: string,
    runId: string | undefined,
    stepId: string | undefined,
    actor: ScriptArtifactActor,
  ): void {
    const passed = validation.tests.filter((test) => test.status === "passed");
    const failed = validation.tests.filter((test) => test.status === "failed");
    if (validation.state === "linted" && passed.length === 0) {
      throw new ScriptArtifactError("script_validation_evidence_required", "Linted scripts require at least one attributable passed validation record", "evidence_insufficient", 409);
    }
    if (["tested", "approved"].includes(validation.state) && (passed.length === 0 || !validation.testArtifactId)) {
      throw new ScriptArtifactError("script_test_artifact_required", `${validation.state} scripts require passed tests and a canonical test-result artifact`, "evidence_insufficient", 409);
    }
    if (validation.state === "approved" && (failed.length > 0 || validation.tests.some((test) => test.status === "not_run"))) {
      throw new ScriptArtifactError("script_approval_tests_incomplete", "Approved script metadata cannot contain failed or unexecuted tests", "evidence_insufficient", 409);
    }
    if (validation.state === "rejected" && failed.length === 0) {
      throw new ScriptArtifactError("script_rejection_evidence_required", "Rejected script metadata requires at least one failed validation record", "evidence_insufficient", 409);
    }
    if (validation.testArtifactId) this.assertTestArtifact(missionId, runId, stepId, validation.testArtifactId);
    if (inputs.some((input) => input.sensitivity === "secret_reference") && !/(?:environment|runtime|vault|secret manager|credential reference|operator-supplied)/iu.test(secretsHandling)) {
      throw new ScriptArtifactError(
        "script_secret_handling_incomplete",
        "Secret-reference inputs require an explicit runtime, environment, vault, or credential-reference handling statement",
        "secret_handling",
        400,
      );
    }
    if (provenance.origin === "imported" && provenance.sourceRefs.length === 0) {
      throw new ScriptArtifactError("script_import_provenance_required", "Imported scripts require at least one immutable source reference");
    }
    if (provenance.origin === "agent_generated" && !provenance.authorAgentId) {
      throw new ScriptArtifactError("script_author_agent_required", "Agent-generated scripts require an attributable authorAgentId");
    }
    if (actor.type === "agent" && provenance.authorAgentId !== actor.id) {
      throw new ScriptArtifactError("script_authorship_mismatch", "An agent may only author script provenance under its own canonical identity", "policy_denied", 403);
    }
    if (actor.type === "agent" && provenance.origin === "operator_authored") {
      throw new ScriptArtifactError("script_authorship_mismatch", "Agent-created records cannot claim operator authorship", "policy_denied", 403);
    }
    if (provenance.authorAgentId) this.assertAgent(provenance.authorAgentId);
  }

  private assertMission(missionId: string, mutable: boolean): MissionRow {
    const row = this.database.prepare("SELECT journey, control_plane FROM missions WHERE id = ?").get(missionId) as MissionRow | undefined;
    if (!row) throw new ScriptArtifactError("script_mission_not_found", `Mission not found: ${missionId}`, "not_found", 404);
    if (mutable && row.control_plane !== "ti_scale") {
      throw conflict("script_control_plane_conflict", "Legacy-controlled missions are read-only in Ti-Scale", "Import or explicitly transfer the mission before creating V2 script versions.");
    }
    return row;
  }

  private assertRun(missionId: string, runId: string, mutable: boolean): RunRow {
    const row = this.database.prepare(`
      SELECT r.mission_id, r.journey, r.control_plane, m.journey AS mission_journey
      FROM runs r JOIN missions m ON m.id = r.mission_id WHERE r.id = ?
    `).get(runId) as RunRow | undefined;
    if (!row) throw new ScriptArtifactError("script_run_not_found", `Run not found: ${runId}`, "not_found", 404);
    if (row.mission_id !== missionId) throw conflict("script_run_scope_mismatch", "Run does not belong to the script mission", "Use a canonical run link from this mission.");
    if (row.journey !== row.mission_journey) throw conflict("script_run_journey_mismatch", "Run journey does not match its canonical mission", "Repair the run/mission relationship before attaching script records.");
    if (mutable && row.control_plane !== "ti_scale") {
      throw conflict("script_control_plane_conflict", "Legacy-controlled runs are read-only in Ti-Scale", "Transfer run ownership before creating V2 script versions.");
    }
    return row;
  }

  private assertPlan(missionId: string, runId: string | undefined, planId: string): PlanRow {
    const row = this.database.prepare(`
      SELECT r.mission_id, p.run_id FROM plans p JOIN runs r ON r.id = p.run_id WHERE p.id = ?
    `).get(planId) as PlanRow | undefined;
    if (!row) throw new ScriptArtifactError("script_plan_not_found", `Plan not found: ${planId}`, "not_found", 404);
    if (row.mission_id !== missionId || (runId && row.run_id !== runId)) {
      throw conflict("script_plan_scope_mismatch", "Plan is outside the script mission/run", "Use the plan attached to this run.");
    }
    return row;
  }

  private assertStep(missionId: string, runId: string | undefined, planId: string | undefined, stepId: string): StepRow {
    const row = this.database.prepare(`
      SELECT r.mission_id, ps.run_id, ps.plan_id
      FROM plan_steps ps JOIN runs r ON r.id = ps.run_id WHERE ps.id = ?
    `).get(stepId) as StepRow | undefined;
    if (!row) throw new ScriptArtifactError("script_step_not_found", `Step not found: ${stepId}`, "not_found", 404);
    if (row.mission_id !== missionId || (runId && row.run_id !== runId) || (planId && row.plan_id !== planId)) {
      throw conflict("script_step_scope_mismatch", "Step is outside the script mission/run/plan", "Use a step from the selected plan.");
    }
    return row;
  }

  private assertTarget(missionId: string, runId: string | undefined, targetNodeId: string, mutable: boolean): TargetRow {
    const row = this.database.prepare("SELECT mission_id, run_id, scope_status FROM topology_nodes WHERE id = ?")
      .get(targetNodeId) as TargetRow | undefined;
    if (!row) throw new ScriptArtifactError("script_target_not_found", `Target node not found: ${targetNodeId}`, "not_found", 404);
    if (
      row.mission_id !== missionId
      || (runId ? Boolean(row.run_id && row.run_id !== runId) : row.run_id !== null)
    ) {
      throw conflict("script_target_scope_mismatch", "Target node is outside the script mission/run", "Use an authorized topology node from this mission.");
    }
    if (mutable && row.scope_status !== "allowed") {
      throw conflict("script_target_not_authorized", "Script metadata cannot target a prohibited, unknown, or out-of-scope node", "Select a normalized allowed target; this service does not expand authorization.");
    }
    return row;
  }

  private assertAttempt(input: Pick<ScriptArtifactSummary, "missionId" | "runId" | "planId" | "stepId" | "attackAttemptId" | "targetNodeId">): void {
    const row = this.database.prepare(`
      SELECT mission_id, run_id, plan_id, step_id, target_asset_id, target_service_id
      FROM attack_attempts WHERE id = ?
    `).get(input.attackAttemptId!) as AttemptRow | undefined;
    if (!row) throw new ScriptArtifactError("script_attack_attempt_not_found", `Attack attempt not found: ${input.attackAttemptId}`, "not_found", 404);
    if (
      row.mission_id !== input.missionId
      || row.run_id !== input.runId
      || (input.planId && row.plan_id !== input.planId)
      || (input.stepId && row.step_id !== input.stepId)
      || (input.targetNodeId && row.target_asset_id !== input.targetNodeId && row.target_service_id !== input.targetNodeId)
    ) throw conflict("script_attack_attempt_scope_mismatch", "Attack attempt is outside the script mission/run/plan/step/target scope", "Use the canonical attempt associated with these exact references.");
  }

  private assertTestArtifact(missionId: string, runId: string | undefined, stepId: string | undefined, artifactId: string): void {
    const row = this.database.prepare("SELECT mission_id, run_id, step_id, artifact_type FROM artifacts WHERE id = ?")
      .get(artifactId) as ArtifactScopeRow | undefined;
    if (!row) throw new ScriptArtifactError("script_test_artifact_not_found", `Test artifact not found: ${artifactId}`, "not_found", 404);
    if (
      row.mission_id !== missionId
      || row.run_id !== (runId ?? null)
      || (row.step_id !== null && row.step_id !== (stepId ?? null))
    ) throw conflict("script_test_artifact_scope_mismatch", "Test artifact is outside the script mission/run/step scope", "Use a canonical test artifact from this exact execution scope.");
    if (!TEST_ARTIFACT_TYPES.has(row.artifact_type)) {
      throw new ScriptArtifactError("script_test_artifact_type_mismatch", "Validation reference is not a canonical script test-result artifact", "evidence_insufficient", 409);
    }
  }

  private assertAgent(agentId: string): void {
    if (!this.database.prepare("SELECT id FROM agents WHERE id = ?").get(agentId)) {
      throw new ScriptArtifactError("script_author_agent_not_found", `Author agent not found: ${agentId}`, "not_found", 404);
    }
  }

  private recordMutation(
    record: ScriptArtifactSummary,
    actor: ScriptArtifactActor,
    action: string,
    reason: string,
    occurredAt: string,
  ): void {
    this.audit.append({
      missionId: record.missionId,
      ...(record.runId ? { runId: record.runId } : {}),
      actor,
      action,
      resourceType: "script_artifact",
      resourceId: record.id,
      reason,
      details: {
        artifactId: record.artifactId,
        name: record.name,
        language: record.language,
        version: record.version,
        contentHash: record.contentHash,
        validationState: record.validation.state,
        testArtifactId: record.validation.testArtifactId ?? null,
        planId: record.planId ?? null,
        stepId: record.stepId ?? null,
        targetNodeId: record.targetNodeId ?? null,
        attackAttemptId: record.attackAttemptId ?? null,
        sourceChanged: record.diff.sourceChanged,
        changedFields: record.diff.changedFields,
        executionPerformed: false,
      },
      occurredAt,
    });
    if (!record.runId) return;
    this.events.append({
      missionId: record.missionId,
      runId: record.runId,
      eventType: action,
      occurredAt,
      actorType: actor.type,
      actorId: actor.id,
      summary: `Documented immutable ${record.name} version ${record.version}; no execution was performed`,
      payload: {
        scriptArtifactId: record.id,
        artifactId: record.artifactId,
        planId: record.planId ?? null,
        stepId: record.stepId ?? null,
        targetNodeId: record.targetNodeId ?? null,
        version: record.version,
        contentHash: record.contentHash,
        validationState: record.validation.state,
        executionPerformed: false,
      },
      schemaVersion: 1,
      journey: undefined,
      sensitivity: record.sensitivity,
      redaction: { sourcePersistedOutsideEvent: true },
      outboxTopic: "run.script-artifacts",
    });
  }
}
