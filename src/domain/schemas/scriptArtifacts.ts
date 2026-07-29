import type {
  ScriptArtifactDetail,
  ScriptArtifactDetailResponse,
  ScriptArtifactList,
  ScriptArtifactSummary,
  ScriptExpectedOutput,
  ScriptLanguage,
  ScriptParameter,
  ScriptRiskClass,
  ScriptValidationState,
} from "../types/scriptArtifacts";
import type { OperationalSensitivity } from "../types/operationalTruth";

type UnknownRecord = Record<string, unknown>;
const LANGUAGES = new Set<ScriptLanguage>(["bash", "c", "cpp", "csharp", "go", "java", "javascript", "lua", "perl", "powershell", "python", "ruby", "rust", "sql", "typescript"]);
const RISKS = new Set<ScriptRiskClass>(["low", "medium", "high", "critical"]);
const VALIDATION = new Set<ScriptValidationState>(["unvalidated", "linted", "tested", "approved", "rejected"]);
const SENSITIVITIES = new Set<OperationalSensitivity>(["public", "internal", "private", "restricted"]);
const SHA256 = /^[a-f0-9]{64}$/u;

function exact(value: unknown, label: string, required: readonly string[], optional: readonly string[] = []): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const item = value as UnknownRecord;
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(item)) if (!allowed.has(key)) throw new Error(`${label} contains unsupported field ${key}`);
  for (const key of required) if (!Object.prototype.hasOwnProperty.call(item, key)) throw new Error(`${label} is missing ${key}`);
  return item;
}

function text(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && !value.trim()) || value.length > 1_000_000) throw new Error(`${label} must be a bounded string`);
  return value;
}

function id(value: unknown, label: string): string {
  const result = text(value, label);
  if (result.length > 240 || /[\u0000-\u001f\u007f]/u.test(result)) throw new Error(`${label} is invalid`);
  return result;
}

function optionalId(value: unknown, label: string): string | undefined { return value === undefined ? undefined : id(value, label); }
function integer(value: unknown, label: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new Error(`${label} must be an integer of at least ${minimum}`);
  return value as number;
}
function bool(value: unknown, label: string): boolean { if (typeof value !== "boolean") throw new Error(`${label} must be boolean`); return value; }
function timestamp(value: unknown, label: string): string { const result = text(value, label); if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO timestamp`); return result; }
function enumValue<T extends string>(value: unknown, values: ReadonlySet<T>, label: string): T { const result = text(value, label) as T; if (!values.has(result)) throw new Error(`${label} is invalid`); return result; }
function hash(value: unknown, label: string): string { const result = text(value, label); if (!SHA256.test(result)) throw new Error(`${label} must be a lowercase SHA-256 digest`); return result; }
function strings(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 1_000) throw new Error(`${label} must be a bounded array`);
  const result = value.map((entry, index) => text(entry, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new Error(`${label} must not contain duplicates`);
  return result;
}

function parameter(value: unknown, index: number): ScriptParameter {
  const item = exact(value, `script input ${index + 1}`, ["name", "description", "required", "sensitivity"]);
  const sensitivity = enumValue(item.sensitivity, new Set(["ordinary", "secret_reference"] as const), `script input ${index + 1}.sensitivity`);
  return { name: text(item.name, `script input ${index + 1}.name`), description: text(item.description, `script input ${index + 1}.description`), required: bool(item.required, `script input ${index + 1}.required`), sensitivity };
}

function expectedOutput(value: unknown, index: number): ScriptExpectedOutput {
  const item = exact(value, `script output ${index + 1}`, ["label", "description", "successRecognition", "failureRecognition"]);
  return {
    label: text(item.label, `script output ${index + 1}.label`),
    description: text(item.description, `script output ${index + 1}.description`),
    successRecognition: text(item.successRecognition, `script output ${index + 1}.successRecognition`),
    failureRecognition: text(item.failureRecognition, `script output ${index + 1}.failureRecognition`),
  };
}

function parseScript(value: unknown, withSource: boolean): ScriptArtifactSummary | ScriptArtifactDetail {
  const required = [
    "id", "missionId", "artifactId", "name", "language", "version", "contentHash", "byteSize", "mediaType", "sensitivity",
    "laymanExplanation", "technicalPurpose", "inputs", "expectedOutputs", "requirements", "touches", "risk", "cleanupNotes",
    "secretsHandling", "evidenceExpectations", "validation", "provenance", "diff", "storageUri", "createdBy", "createdAt",
    ...(withSource ? ["source"] : []),
  ];
  const item = exact(value, "script artifact", required, ["runId", "planId", "stepId", "attackAttemptId", "targetNodeId"]);
  if (!Array.isArray(item.inputs) || item.inputs.length > 100) throw new Error("script inputs must be a bounded array");
  if (!Array.isArray(item.expectedOutputs) || item.expectedOutputs.length > 100) throw new Error("script outputs must be a bounded array");
  const requirements = exact(item.requirements, "script requirements", ["prerequisites", "dependencies"]);
  const touches = exact(item.touches, "script touches", ["files", "network", "services"]);
  const risk = exact(item.risk, "script risk", ["riskClass", "sideEffects", "reversibility"]);
  const validation = exact(item.validation, "script validation", ["state", "summary", "tests"], ["testArtifactId"]);
  if (!Array.isArray(validation.tests) || validation.tests.length > 100) throw new Error("script tests must be a bounded array");
  const tests = validation.tests.map((candidate, index) => {
    const test = exact(candidate, `script test ${index + 1}`, ["name", "status", "summary"]);
    return {
      name: text(test.name, `script test ${index + 1}.name`),
      status: enumValue(test.status, new Set(["not_run", "passed", "failed"] as const), `script test ${index + 1}.status`),
      summary: text(test.summary, `script test ${index + 1}.summary`),
    };
  });
  const provenance = exact(item.provenance, "script provenance", ["origin", "explanation", "sourceRefs", "createdBy", "createdByType"], ["authorAgentId"]);
  const diff = exact(item.diff, "script diff", ["toVersion", "contentHash", "sourceChanged", "changedFields", "commonPrefixLines", "commonSuffixLines", "removedLineCount", "addedLineCount", "changeSummary"], ["previousScriptArtifactId", "fromVersion", "previousContentHash"]);
  const version = integer(item.version, "script version", 1);
  const contentHash = hash(item.contentHash, "script content hash");
  const toVersion = integer(diff.toVersion, "script diff target version", 1);
  if (version !== toVersion || hash(diff.contentHash, "script diff content hash") !== contentHash) throw new Error("script diff does not match the artifact version");
  const fromVersion = diff.fromVersion === undefined ? undefined : integer(diff.fromVersion, "script diff source version", 1);
  const previousScriptArtifactId = optionalId(diff.previousScriptArtifactId, "previous script artifact ID");
  if ((version === 1 && (fromVersion !== undefined || previousScriptArtifactId)) || (version > 1 && (fromVersion !== version - 1 || !previousScriptArtifactId))) throw new Error("script version chain is inconsistent");
  const base: ScriptArtifactSummary = {
    id: id(item.id, "script artifact ID"), missionId: id(item.missionId, "script mission ID"),
    ...(optionalId(item.runId, "script run ID") ? { runId: optionalId(item.runId, "script run ID") } : {}),
    ...(optionalId(item.planId, "script plan ID") ? { planId: optionalId(item.planId, "script plan ID") } : {}),
    ...(optionalId(item.stepId, "script step ID") ? { stepId: optionalId(item.stepId, "script step ID") } : {}),
    ...(optionalId(item.attackAttemptId, "script attempt ID") ? { attackAttemptId: optionalId(item.attackAttemptId, "script attempt ID") } : {}),
    ...(optionalId(item.targetNodeId, "script target ID") ? { targetNodeId: optionalId(item.targetNodeId, "script target ID") } : {}),
    artifactId: id(item.artifactId, "source artifact ID"), name: text(item.name, "script name"),
    language: enumValue(item.language, LANGUAGES, "script language"), version, contentHash,
    byteSize: integer(item.byteSize, "script byte size", 1), mediaType: text(item.mediaType, "script media type"),
    sensitivity: enumValue(item.sensitivity, SENSITIVITIES, "script sensitivity"),
    laymanExplanation: text(item.laymanExplanation, "script layman explanation"), technicalPurpose: text(item.technicalPurpose, "script technical purpose"),
    inputs: item.inputs.map(parameter), expectedOutputs: item.expectedOutputs.map(expectedOutput),
    requirements: { prerequisites: strings(requirements.prerequisites, "script prerequisites"), dependencies: strings(requirements.dependencies, "script dependencies") },
    touches: { files: strings(touches.files, "script touched files"), network: strings(touches.network, "script touched network"), services: strings(touches.services, "script touched services") },
    risk: { riskClass: enumValue(risk.riskClass, RISKS, "script risk class"), sideEffects: strings(risk.sideEffects, "script side effects"), reversibility: text(risk.reversibility, "script reversibility") },
    cleanupNotes: text(item.cleanupNotes, "script cleanup notes"), secretsHandling: text(item.secretsHandling, "script secrets handling"), evidenceExpectations: strings(item.evidenceExpectations, "script evidence expectations"),
    validation: { state: enumValue(validation.state, VALIDATION, "script validation state"), summary: text(validation.summary, "script validation summary"), tests, ...(optionalId(validation.testArtifactId, "script test artifact ID") ? { testArtifactId: optionalId(validation.testArtifactId, "script test artifact ID") } : {}) },
    provenance: {
      origin: enumValue(provenance.origin, new Set(["operator_authored", "agent_generated", "imported", "modified"] as const), "script origin"),
      explanation: text(provenance.explanation, "script provenance explanation"), sourceRefs: strings(provenance.sourceRefs, "script source references"),
      ...(optionalId(provenance.authorAgentId, "script author agent ID") ? { authorAgentId: optionalId(provenance.authorAgentId, "script author agent ID") } : {}),
      createdBy: id(provenance.createdBy, "script provenance actor"), createdByType: enumValue(provenance.createdByType, new Set(["operator", "agent", "worker", "system"] as const), "script actor type"),
    },
    diff: {
      ...(previousScriptArtifactId ? { previousScriptArtifactId } : {}), ...(fromVersion === undefined ? {} : { fromVersion }),
      toVersion, ...(diff.previousContentHash === undefined ? {} : { previousContentHash: hash(diff.previousContentHash, "previous script content hash") }),
      contentHash, sourceChanged: bool(diff.sourceChanged, "script source changed"), changedFields: strings(diff.changedFields, "script changed fields"),
      commonPrefixLines: integer(diff.commonPrefixLines, "common prefix lines"), commonSuffixLines: integer(diff.commonSuffixLines, "common suffix lines"),
      removedLineCount: integer(diff.removedLineCount, "removed line count"), addedLineCount: integer(diff.addedLineCount, "added line count"), changeSummary: text(diff.changeSummary, "script change summary"),
    },
    storageUri: text(item.storageUri, "script storage URI"), createdBy: id(item.createdBy, "script created-by actor"), createdAt: timestamp(item.createdAt, "script created time"),
  };
  if (base.createdBy !== base.provenance.createdBy) throw new Error("script provenance actor does not match createdBy");
  return withSource ? { ...base, source: text(item.source, "script source", true) } : base;
}

export function parseScriptArtifactList(value: unknown): ScriptArtifactList {
  const root = exact(value, "script artifact list", ["schemaVersion", "items"]);
  if (root.schemaVersion !== "2.4") throw new Error("unsupported script-artifact schema version");
  if (!Array.isArray(root.items) || root.items.length > 100) throw new Error("script artifact list must contain at most 100 items");
  return { schemaVersion: "2.4", items: root.items.map((item) => parseScript(item, false) as ScriptArtifactSummary) };
}

export function parseScriptArtifactDetail(value: unknown): ScriptArtifactDetailResponse {
  const root = exact(value, "script artifact detail", ["schemaVersion", "record"]);
  if (root.schemaVersion !== "2.4") throw new Error("unsupported script-artifact schema version");
  return { schemaVersion: "2.4", record: parseScript(root.record, true) as ScriptArtifactDetail };
}
