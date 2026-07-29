import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { canonicalJson } from "../run-intelligence/serialization";
import type {
  ScriptArtifactActor,
  ScriptArtifactListFilter,
  ScriptArtifactSummary,
  ScriptExpectedOutput,
  ScriptLanguage,
  ScriptParameter,
  ScriptProvenance,
  ScriptRiskDocumentation,
  ScriptTouches,
  ScriptValidationDocumentation,
  ScriptVersionDiff,
} from "./types";
import { ScriptArtifactError } from "./types";

interface ScriptArtifactRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly plan_id: string | null;
  readonly step_id: string | null;
  readonly attack_attempt_id: string | null;
  readonly target_node_id: string | null;
  readonly artifact_id: string;
  readonly name: string;
  readonly language: ScriptLanguage;
  readonly version: number;
  readonly content_hash: string;
  readonly layman_explanation: string;
  readonly technical_purpose: string;
  readonly inputs_json: string;
  readonly expected_outputs_json: string;
  readonly prerequisites_json: string;
  readonly touches_json: string;
  readonly side_effects_json: string;
  readonly cleanup_notes: string;
  readonly secrets_handling: string;
  readonly evidence_expectations_json: string;
  readonly validation_state: ScriptValidationDocumentation["state"];
  readonly test_artifact_id: string | null;
  readonly created_by: string;
  readonly created_at: string;
  readonly storage_uri: string;
  readonly byte_size: number;
  readonly media_type: string | null;
  readonly sensitivity: ScriptArtifactSummary["sensitivity"];
  readonly metadata_json: string;
  readonly artifact_mission_id: string;
  readonly artifact_run_id: string | null;
  readonly artifact_step_id: string | null;
  readonly artifact_journey: "autonomous" | "guided";
  readonly artifact_type: string;
  readonly artifact_content_hash: string;
  readonly artifact_created_at: string;
}

interface ScriptMetadata {
  readonly schemaVersion: "2.4";
  readonly artifactRole: "immutable_script_source";
  readonly validation: ScriptValidationDocumentation;
  readonly provenance: ScriptProvenance & {
    readonly createdBy: string;
    readonly createdByType: ScriptArtifactActor["type"];
  };
  readonly diff: ScriptVersionDiff;
}

export interface PersistScriptArtifactInput {
  readonly id: string;
  readonly artifactId: string;
  readonly missionId: string;
  readonly journey: "autonomous" | "guided";
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly attackAttemptId?: string;
  readonly targetNodeId?: string;
  readonly name: string;
  readonly language: ScriptLanguage;
  readonly version: number;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly mediaType: string;
  readonly storageUri: string;
  readonly sensitivity: ScriptArtifactSummary["sensitivity"];
  readonly laymanExplanation: string;
  readonly technicalPurpose: string;
  readonly inputs: readonly ScriptParameter[];
  readonly expectedOutputs: readonly ScriptExpectedOutput[];
  readonly prerequisites: readonly string[];
  readonly dependencies: readonly string[];
  readonly touches: ScriptTouches;
  readonly risk: ScriptRiskDocumentation;
  readonly cleanupNotes: string;
  readonly secretsHandling: string;
  readonly evidenceExpectations: readonly string[];
  readonly validation: ScriptValidationDocumentation;
  readonly provenance: ScriptProvenance;
  readonly actor: ScriptArtifactActor;
  readonly diff: ScriptVersionDiff;
  readonly createdAt: string;
}

function corrupt(message: string): never {
  throw new ScriptArtifactError("script_artifact_record_corrupt", message, "data_integrity", 500);
}

function object(value: unknown, label: string): Readonly<Record<string, unknown>> {
  if (!value || typeof value !== "object" || Array.isArray(value)) corrupt(`Stored ${label} is malformed`);
  return value as Readonly<Record<string, unknown>>;
}

function parsed(serialized: string, label: string): unknown {
  try { return JSON.parse(serialized) as unknown; } catch { return corrupt(`Stored ${label} is not valid JSON`); }
}

function stringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) corrupt(`Stored ${label} is malformed`);
  return value as readonly string[];
}

function parameters(value: unknown): readonly ScriptParameter[] {
  if (!Array.isArray(value)) corrupt("Stored script inputs are malformed");
  return value.map((raw) => {
    const item = object(raw, "script input");
    if (
      typeof item.name !== "string" || typeof item.description !== "string"
      || typeof item.required !== "boolean"
      || !["ordinary", "secret_reference"].includes(String(item.sensitivity))
    ) corrupt("Stored script input is incomplete");
    return item as unknown as ScriptParameter;
  });
}

function outputs(value: unknown): readonly ScriptExpectedOutput[] {
  if (!Array.isArray(value)) corrupt("Stored expected outputs are malformed");
  return value.map((raw) => {
    const item = object(raw, "expected output");
    if ([item.label, item.description, item.successRecognition, item.failureRecognition].some((entry) => typeof entry !== "string")) {
      corrupt("Stored expected output is incomplete");
    }
    return item as unknown as ScriptExpectedOutput;
  });
}

function metadata(serialized: string): ScriptMetadata {
  const root = object(parsed(serialized, "script artifact metadata"), "script artifact metadata");
  if (root.schemaVersion !== "2.4" || root.artifactRole !== "immutable_script_source") {
    corrupt("Stored script artifact metadata has an unsupported schema");
  }
  const validation = object(root.validation, "script validation");
  const tests = validation.tests;
  if (
    !["unvalidated", "linted", "tested", "approved", "rejected"].includes(String(validation.state))
    || typeof validation.summary !== "string"
    || !Array.isArray(tests)
    || !tests.every((raw) => {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
      const test = raw as Record<string, unknown>;
      return typeof test.name === "string"
        && ["not_run", "passed", "failed"].includes(String(test.status))
        && typeof test.summary === "string";
    })
    || (validation.testArtifactId !== undefined && typeof validation.testArtifactId !== "string")
  ) corrupt("Stored script validation metadata is malformed");

  const provenance = object(root.provenance, "script provenance");
  if (
    !["operator_authored", "agent_generated", "imported", "modified"].includes(String(provenance.origin))
    || typeof provenance.explanation !== "string"
    || !Array.isArray(provenance.sourceRefs)
    || !provenance.sourceRefs.every((item) => typeof item === "string")
    || typeof provenance.createdBy !== "string"
    || !["operator", "agent", "worker", "system"].includes(String(provenance.createdByType))
    || (provenance.authorAgentId !== undefined && typeof provenance.authorAgentId !== "string")
  ) corrupt("Stored script provenance metadata is malformed");

  const diff = object(root.diff, "script version diff");
  if (
    typeof diff.toVersion !== "number"
    || typeof diff.contentHash !== "string"
    || typeof diff.sourceChanged !== "boolean"
    || !Array.isArray(diff.changedFields)
    || !diff.changedFields.every((item) => typeof item === "string")
    || [diff.commonPrefixLines, diff.commonSuffixLines, diff.removedLineCount, diff.addedLineCount].some((item) => typeof item !== "number")
    || typeof diff.changeSummary !== "string"
  ) corrupt("Stored script version diff metadata is malformed");
  return root as unknown as ScriptMetadata;
}

function summary(row: ScriptArtifactRow): ScriptArtifactSummary {
  const stored = metadata(row.metadata_json);
  const requirements = object(parsed(row.prerequisites_json, "script requirements"), "script requirements");
  const touches = object(parsed(row.touches_json, "script touches"), "script touches");
  const risk = object(parsed(row.side_effects_json, "script risk"), "script risk");
  if (
    row.artifact_mission_id !== row.mission_id
    || row.artifact_run_id !== row.run_id
    || row.artifact_step_id !== row.step_id
    || row.artifact_type !== "generated_script_source"
    || row.artifact_content_hash !== row.content_hash
    || row.artifact_created_at !== row.created_at
  ) corrupt("Canonical source artifact scope or integrity metadata does not match its script version");
  if (
    !["bash", "c", "cpp", "csharp", "go", "java", "javascript", "lua", "perl", "powershell", "python", "ruby", "rust", "sql", "typescript"].includes(row.language)
    || !/^[a-f0-9]{64}$/u.test(row.content_hash)
    || !Number.isSafeInteger(row.version) || row.version < 1
    || !Number.isSafeInteger(row.byte_size) || row.byte_size < 1
    || !row.media_type
  ) corrupt("Canonical script source type, hash, version, or size is malformed");
  const result: ScriptArtifactSummary = {
    id: row.id,
    missionId: row.mission_id,
    ...(row.run_id ? { runId: row.run_id } : {}),
    ...(row.plan_id ? { planId: row.plan_id } : {}),
    ...(row.step_id ? { stepId: row.step_id } : {}),
    ...(row.attack_attempt_id ? { attackAttemptId: row.attack_attempt_id } : {}),
    ...(row.target_node_id ? { targetNodeId: row.target_node_id } : {}),
    artifactId: row.artifact_id,
    name: row.name,
    language: row.language,
    version: row.version,
    contentHash: row.content_hash,
    byteSize: row.byte_size,
    mediaType: row.media_type ?? "application/octet-stream",
    sensitivity: row.sensitivity,
    laymanExplanation: row.layman_explanation,
    technicalPurpose: row.technical_purpose,
    inputs: parameters(parsed(row.inputs_json, "script inputs")),
    expectedOutputs: outputs(parsed(row.expected_outputs_json, "expected outputs")),
    requirements: {
      prerequisites: stringArray(requirements.prerequisites, "script prerequisites"),
      dependencies: stringArray(requirements.dependencies, "script dependencies"),
    },
    touches: {
      files: stringArray(touches.files, "touched files"),
      network: stringArray(touches.network, "touched network resources"),
      services: stringArray(touches.services, "touched services"),
    },
    risk: {
      riskClass: risk.riskClass as ScriptRiskDocumentation["riskClass"],
      sideEffects: stringArray(risk.sideEffects, "script side effects"),
      reversibility: typeof risk.reversibility === "string" ? risk.reversibility : corrupt("Stored script reversibility is malformed"),
    },
    cleanupNotes: row.cleanup_notes,
    secretsHandling: row.secrets_handling,
    evidenceExpectations: stringArray(parsed(row.evidence_expectations_json, "evidence expectations"), "evidence expectations"),
    validation: stored.validation,
    provenance: stored.provenance,
    diff: stored.diff,
    storageUri: row.storage_uri,
    createdBy: row.created_by,
    createdAt: row.created_at,
  };
  if (result.validation.state !== row.validation_state || result.validation.testArtifactId !== (row.test_artifact_id ?? undefined)) {
    corrupt("Stored script validation metadata does not match canonical columns");
  }
  if (
    result.provenance.createdBy !== row.created_by
    || result.diff.toVersion !== row.version
    || result.diff.contentHash !== row.content_hash
    || (row.version === 1 && (result.diff.fromVersion !== undefined || result.diff.previousScriptArtifactId !== undefined))
    || (row.version > 1 && (result.diff.fromVersion !== row.version - 1 || !result.diff.previousScriptArtifactId))
  ) corrupt("Stored script version provenance or diff does not match canonical columns");
  for (const value of [
    result.diff.toVersion,
    result.diff.commonPrefixLines,
    result.diff.commonSuffixLines,
    result.diff.removedLineCount,
    result.diff.addedLineCount,
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) corrupt("Stored script line-diff counters are malformed");
  }
  if (!["low", "medium", "high", "critical"].includes(result.risk.riskClass)) {
    corrupt("Stored script risk class is malformed");
  }
  return result;
}

const SELECT = `
  SELECT sa.*, a.storage_uri, a.byte_size, a.media_type, a.sensitivity,
    a.metadata_json, a.mission_id AS artifact_mission_id,
    a.run_id AS artifact_run_id, a.step_id AS artifact_step_id,
    a.journey AS artifact_journey, a.artifact_type,
    a.content_hash AS artifact_content_hash, a.created_at AS artifact_created_at
  FROM script_artifacts sa
  JOIN artifacts a ON a.id = sa.artifact_id
`;

/** Prepared-statement repository for immutable script version and source-artifact records. */
export class ScriptArtifactRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly idFactory: (prefix: string) => string = (prefix) => `${prefix}_${randomUUID()}`,
  ) {}

  createIds(): { readonly scriptArtifactId: string; readonly artifactId: string } {
    return { scriptArtifactId: this.idFactory("script"), artifactId: this.idFactory("artifact") };
  }

  get(id: string): ScriptArtifactSummary {
    const row = this.database.prepare(`${SELECT} WHERE sa.id = ?`).get(id) as ScriptArtifactRow | undefined;
    if (!row) throw new ScriptArtifactError("script_artifact_not_found", `Script artifact not found: ${id}`, "not_found", 404, "Use a canonical script link from the selected mission.");
    return summary(row);
  }

  latest(missionId: string, name: string): ScriptArtifactSummary | undefined {
    const row = this.database.prepare(`
      ${SELECT}
      WHERE sa.mission_id = ? AND sa.name = ?
      ORDER BY sa.version DESC, sa.created_at DESC, sa.id
      LIMIT 1
    `).get(missionId, name) as ScriptArtifactRow | undefined;
    return row ? summary(row) : undefined;
  }

  list(filter: ScriptArtifactListFilter): readonly ScriptArtifactSummary[] {
    const predicates = ["sa.mission_id = ?"];
    const values: unknown[] = [filter.missionId];
    if (filter.runId) { predicates.push("sa.run_id = ?"); values.push(filter.runId); }
    if (filter.planId) { predicates.push("sa.plan_id = ?"); values.push(filter.planId); }
    if (filter.stepId) { predicates.push("sa.step_id = ?"); values.push(filter.stepId); }
    if (filter.targetNodeId) { predicates.push("sa.target_node_id = ?"); values.push(filter.targetNodeId); }
    if (filter.language) { predicates.push("sa.language = ?"); values.push(filter.language); }
    if (filter.name) { predicates.push("sa.name = ?"); values.push(filter.name); }
    values.push(filter.limit ?? 100);
    const rows = this.database.prepare(`
      ${SELECT}
      WHERE ${predicates.join(" AND ")}
      ORDER BY sa.created_at DESC, sa.name, sa.version DESC, sa.id
      LIMIT ?
    `).all(...values) as ScriptArtifactRow[];
    return rows.map(summary);
  }

  insert(input: PersistScriptArtifactInput): ScriptArtifactSummary {
    const artifactMetadata: ScriptMetadata = {
      schemaVersion: "2.4",
      artifactRole: "immutable_script_source",
      validation: input.validation,
      provenance: {
        ...input.provenance,
        createdBy: input.actor.id,
        createdByType: input.actor.type,
      },
      diff: input.diff,
    };
    this.database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, step_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
      ) VALUES (?, ?, ?, ?, ?, 'generated_script_source', ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.artifactId,
      input.missionId,
      input.runId ?? null,
      input.stepId ?? null,
      input.journey,
      input.storageUri,
      input.contentHash,
      input.byteSize,
      input.mediaType,
      input.sensitivity,
      canonicalJson(artifactMetadata as never),
      input.createdAt,
    );
    this.database.prepare(`
      INSERT INTO script_artifacts (
        id, mission_id, run_id, plan_id, step_id, attack_attempt_id,
        target_node_id, artifact_id, name, language, version, content_hash,
        layman_explanation, technical_purpose, inputs_json,
        expected_outputs_json, prerequisites_json, touches_json,
        side_effects_json, cleanup_notes, secrets_handling,
        evidence_expectations_json, validation_state, test_artifact_id,
        created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.id,
      input.missionId,
      input.runId ?? null,
      input.planId ?? null,
      input.stepId ?? null,
      input.attackAttemptId ?? null,
      input.targetNodeId ?? null,
      input.artifactId,
      input.name,
      input.language,
      input.version,
      input.contentHash,
      input.laymanExplanation,
      input.technicalPurpose,
      canonicalJson(input.inputs as never),
      canonicalJson(input.expectedOutputs as never),
      canonicalJson({ prerequisites: input.prerequisites, dependencies: input.dependencies } as never),
      canonicalJson(input.touches as never),
      canonicalJson(input.risk as never),
      input.cleanupNotes,
      input.secretsHandling,
      canonicalJson(input.evidenceExpectations as never),
      input.validation.state,
      input.validation.testArtifactId ?? null,
      input.actor.id,
      input.createdAt,
    );
    return this.get(input.id);
  }
}
