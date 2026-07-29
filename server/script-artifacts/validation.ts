import { createHash } from "node:crypto";
import { z } from "zod";
import { redactSecrets } from "../contracts/redaction";
import type {
  CreateScriptArtifactInput,
  CreateScriptVersionInput,
  ScriptArtifactListFilter,
  ScriptLanguage,
} from "./types";
import { ScriptArtifactError } from "./types";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9._:@-]{1,240}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const CONTROL_CHARACTER = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u;
const SOURCE_MAXIMUM_BYTES = 512 * 1024;

const LANGUAGES = [
  "bash", "c", "cpp", "csharp", "go", "java", "javascript", "lua", "perl",
  "powershell", "python", "ruby", "rust", "sql", "typescript",
] as const;

const EXTENSIONS: Readonly<Record<ScriptLanguage, readonly string[]>> = {
  bash: [".sh"],
  c: [".c"],
  cpp: [".cc", ".cpp", ".cxx"],
  csharp: [".cs"],
  go: [".go"],
  java: [".java"],
  javascript: [".js", ".mjs", ".cjs"],
  lua: [".lua"],
  perl: [".pl"],
  powershell: [".ps1"],
  python: [".py"],
  ruby: [".rb"],
  rust: [".rs"],
  sql: [".sql"],
  typescript: [".ts", ".mts", ".cts"],
};

const identifierSchema = z.string().trim().regex(IDENTIFIER_PATTERN);
const languageSchema = z.enum(LANGUAGES);
const sensitivitySchema = z.enum(["public", "internal", "private", "restricted"]);
const riskClassSchema = z.enum(["low", "medium", "high", "critical"]);
const validationStateSchema = z.enum(["unvalidated", "linted", "tested", "approved", "rejected"]);

function safeTextSchema(maximum: number): z.ZodString {
  return z.string().trim().min(1).max(maximum)
    .refine((value) => !CONTROL_CHARACTER.test(value), "must not contain control characters")
    .refine((value) => redactSecrets(value) === value, "must not contain secret-bearing material");
}

const shortText = safeTextSchema(1_000);
const text = safeTextSchema(8_000);

const scriptParameterSchema = z.object({
  name: z.string().trim().min(1).max(120).regex(/^[A-Za-z_][A-Za-z0-9_.-]*$/u),
  description: shortText,
  required: z.boolean(),
  sensitivity: z.enum(["ordinary", "secret_reference"]),
}).strict();

const expectedOutputSchema = z.object({
  label: shortText,
  description: text,
  successRecognition: text,
  failureRecognition: text,
}).strict();

const touchesSchema = z.object({
  files: z.array(shortText).max(100),
  network: z.array(shortText).max(100),
  services: z.array(shortText).max(100),
}).strict();

const testRecordSchema = z.object({
  name: shortText,
  status: z.enum(["not_run", "passed", "failed"]),
  summary: text,
}).strict();

const validationSchema = z.object({
  state: validationStateSchema,
  summary: text,
  tests: z.array(testRecordSchema).max(100),
  testArtifactId: identifierSchema.optional(),
}).strict();

const provenanceSchema = z.object({
  origin: z.enum(["operator_authored", "agent_generated", "imported", "modified"]),
  explanation: text,
  sourceRefs: z.array(safeTextSchema(500)).max(100),
  authorAgentId: identifierSchema.optional(),
}).strict();

const documentationShape = {
  language: languageSchema,
  source: z.string().min(1).refine(
    (value) => Buffer.byteLength(value, "utf8") <= SOURCE_MAXIMUM_BYTES,
    `must not exceed ${SOURCE_MAXIMUM_BYTES} UTF-8 bytes`,
  ),
  laymanExplanation: text,
  technicalPurpose: text,
  inputs: z.array(scriptParameterSchema).max(100),
  expectedOutputs: z.array(expectedOutputSchema).min(1).max(100),
  prerequisites: z.array(shortText).max(100),
  dependencies: z.array(shortText).max(100),
  touches: touchesSchema,
  sideEffects: z.array(shortText).min(1).max(100),
  riskClass: riskClassSchema,
  reversibility: text,
  cleanupNotes: text,
  secretsHandling: text,
  evidenceExpectations: z.array(shortText).min(1).max(100),
  validation: validationSchema,
  provenance: provenanceSchema,
  sensitivity: sensitivitySchema,
} as const;

const createBodySchema = z.object({
  runId: identifierSchema.optional(),
  planId: identifierSchema.optional(),
  stepId: identifierSchema.optional(),
  attackAttemptId: identifierSchema.optional(),
  targetNodeId: identifierSchema.optional(),
  name: z.string().trim().min(1).max(240),
  ...documentationShape,
}).strict();

const canonicalCreateSchema = z.object({
  missionId: identifierSchema,
  runId: identifierSchema.optional(),
  planId: identifierSchema.optional(),
  stepId: identifierSchema.optional(),
  attackAttemptId: identifierSchema.optional(),
  targetNodeId: identifierSchema.optional(),
  name: z.string().trim().min(1).max(240),
  ...documentationShape,
}).strict();

const versionBodySchema = z.object({
  expectedVersion: z.number().int().positive().max(1_000_000),
  changeSummary: text,
  ...documentationShape,
}).strict();

const canonicalVersionSchema = z.object({
  scriptArtifactId: identifierSchema,
  expectedVersion: z.number().int().positive().max(1_000_000),
  changeSummary: text,
  ...documentationShape,
}).strict();

function parsed<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const fields = [...new Set(result.error.issues.map((issue) => issue.path.join(".") || label))];
  throw new ScriptArtifactError(
    "invalid_script_artifact_request",
    `Script artifact request failed validation for: ${fields.slice(0, 12).join(", ")}`,
  );
}

function assertUnique(values: readonly string[], label: string): void {
  const normalized = values.map((value) => value.toLocaleLowerCase("en-US"));
  if (new Set(normalized).size !== normalized.length) {
    throw new ScriptArtifactError("duplicate_script_metadata", `${label} must not contain duplicate values`);
  }
}

function assertUniqueNames(values: readonly { readonly name: string }[], label: string): void {
  assertUnique(values.map(({ name }) => name), label);
}

function safeLiteral(value: string): boolean {
  const normalized = value.trim();
  return normalized === ""
    || /^<(?:(?:API_?)?KEY|CREDENTIAL|PASSWORD|SECRET|TOKEN)>$/iu.test(normalized)
    || /^\[?REDACTED(?:-[A-Z-]+)?\]?$/iu.test(normalized)
    || /^\$\{?[A-Z_][A-Z0-9_]*\}?$/u.test(normalized);
}

/** Reject known tokens, private keys, credential-bearing URIs, and literal secret assignments. */
export function assertNoEmbeddedSecrets(source: string): void {
  const knownSecretPatterns: readonly RegExp[] = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
    /\bsk-[A-Za-z0-9_-]{12,}\b/u,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/u,
    /\bAKIA[0-9A-Z]{16}\b/u,
    /\bhttps?:\/\/[^\s/:@]+:[^\s/@]+@/iu,
    /\bAuthorization\s*[:=]\s*["'`]?(?:Bearer|Basic)\s+(?!\$|<|\{)[A-Za-z0-9+/_.=-]{8,}/iu,
    /(?:--password|--passwd|--token|--api[_-]?key|--secret)\s+(?!\$|<|\{)[^\s"']{4,}/iu,
  ];
  if (knownSecretPatterns.some((pattern) => pattern.test(source))) {
    throw new ScriptArtifactError(
      "embedded_script_secret_rejected",
      "Script source contains credential-like material and was not retained",
      "secret_handling",
      400,
      "Replace the value with an opaque runtime reference such as an environment or vault lookup.",
    );
  }

  const assignment = /\b(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)(?:[_-][A-Za-z0-9]+)*\b\s*[:=]\s*(["'`])([^\n\r"'`]*)\1/giu;
  for (const match of source.matchAll(assignment)) {
    if (!safeLiteral(match[2] ?? "")) {
      throw new ScriptArtifactError(
        "embedded_script_secret_rejected",
        "Script source contains a literal assigned to a credential-like field and was not retained",
        "secret_handling",
        400,
        "Read the value from an approved runtime secret reference instead of embedding it in source.",
      );
    }
  }
}

export function safeScriptName(value: string, language: ScriptLanguage): string {
  const normalized = value.trim();
  if (
    normalized.startsWith("/")
    || normalized.includes("\\")
    || /^[A-Za-z]:/u.test(normalized)
    || CONTROL_CHARACTER.test(normalized)
  ) {
    throw new ScriptArtifactError("unsafe_script_source_path", "Script name must be a safe relative POSIX path");
  }
  const components = normalized.split("/");
  if (
    components.length > 12
    || components.some((component) => !component || component === "." || component === ".." || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(component))
  ) {
    throw new ScriptArtifactError("unsafe_script_source_path", "Script name contains an unsafe or ambiguous path component");
  }
  const lower = normalized.toLocaleLowerCase("en-US");
  if ([".env", ".pem", ".key", ".p12", ".pfx"].some((suffix) => lower.endsWith(suffix))) {
    throw new ScriptArtifactError("unsafe_script_source_path", "Script source cannot use a secret or key-material filename");
  }
  if (!EXTENSIONS[language].some((extension) => lower.endsWith(extension))) {
    throw new ScriptArtifactError(
      "script_language_path_mismatch",
      `Script name must use a ${language} source extension (${EXTENSIONS[language].join(", ")})`,
    );
  }
  return normalized;
}

function normalizeCreate(input: CreateScriptArtifactInput): CreateScriptArtifactInput {
  assertNoEmbeddedSecrets(input.source);
  const name = safeScriptName(input.name, input.language);
  assertUniqueNames(input.inputs, "Script inputs");
  assertUnique(input.prerequisites, "Script prerequisites");
  assertUnique(input.dependencies, "Script dependencies");
  assertUnique(input.touches.files, "Touched files");
  assertUnique(input.touches.network, "Touched network resources");
  assertUnique(input.touches.services, "Touched services");
  assertUnique(input.sideEffects, "Script side effects");
  assertUniqueNames(input.validation.tests, "Script tests");
  assertUnique(input.evidenceExpectations, "Evidence expectations");
  assertUnique(input.provenance.sourceRefs, "Provenance source references");
  return { ...input, name };
}

function normalizeVersion(input: CreateScriptVersionInput): CreateScriptVersionInput {
  assertNoEmbeddedSecrets(input.source);
  assertUniqueNames(input.inputs, "Script inputs");
  assertUnique(input.prerequisites, "Script prerequisites");
  assertUnique(input.dependencies, "Script dependencies");
  assertUnique(input.touches.files, "Touched files");
  assertUnique(input.touches.network, "Touched network resources");
  assertUnique(input.touches.services, "Touched services");
  assertUnique(input.sideEffects, "Script side effects");
  assertUniqueNames(input.validation.tests, "Script tests");
  assertUnique(input.evidenceExpectations, "Evidence expectations");
  assertUnique(input.provenance.sourceRefs, "Provenance source references");
  return input;
}

export function validateCreateScriptArtifactInput(value: unknown): CreateScriptArtifactInput {
  return normalizeCreate(parsed(canonicalCreateSchema, value, "body") as CreateScriptArtifactInput);
}

export function parseCreateScriptArtifactInput(missionId: string, value: unknown): CreateScriptArtifactInput {
  const body = parsed(createBodySchema, value, "body") as Omit<CreateScriptArtifactInput, "missionId">;
  return validateCreateScriptArtifactInput({ missionId, ...body });
}

export function validateCreateScriptVersionInput(value: unknown): CreateScriptVersionInput {
  return normalizeVersion(parsed(canonicalVersionSchema, value, "body") as CreateScriptVersionInput);
}

export function parseCreateScriptVersionInput(scriptArtifactId: string, value: unknown): CreateScriptVersionInput {
  const body = parsed(versionBodySchema, value, "body") as Omit<CreateScriptVersionInput, "scriptArtifactId">;
  return validateCreateScriptVersionInput({ scriptArtifactId, ...body });
}

export function scriptIdentifier(value: unknown, label: string): string {
  const result = identifierSchema.safeParse(value);
  if (!result.success) throw new ScriptArtifactError("invalid_script_artifact_identifier", `${label} is invalid`);
  return result.data;
}

export function requiredScriptIdempotencyKey(value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized || !IDEMPOTENCY_KEY.test(normalized)) {
    throw new ScriptArtifactError(
      "script_artifact_idempotency_key_required",
      "A unique Idempotency-Key containing 8-200 safe characters is required",
    );
  }
  return normalized;
}

export function scriptArtifactListFilter(missionId: string, query: Record<string, unknown>): ScriptArtifactListFilter {
  const allowed = new Set(["runId", "planId", "stepId", "targetNodeId", "language", "name", "limit"]);
  for (const key of Object.keys(query)) {
    if (!allowed.has(key)) throw new ScriptArtifactError("invalid_script_artifact_query", `Unsupported script artifact query field: ${key}`);
  }
  const one = (key: string): string | undefined => {
    const value = query[key];
    if (value === undefined || value === "") return undefined;
    if (typeof value !== "string") throw new ScriptArtifactError("invalid_script_artifact_query", `${key} must occur exactly once`);
    return value;
  };
  const runId = one("runId");
  const planId = one("planId");
  const stepId = one("stepId");
  const targetNodeId = one("targetNodeId");
  const languageValue = one("language");
  const nameValue = one("name");
  const languageResult = languageValue === undefined ? undefined : languageSchema.safeParse(languageValue);
  if (languageResult && !languageResult.success) throw new ScriptArtifactError("invalid_script_artifact_query", "language is unsupported");
  if (nameValue && (nameValue.length > 240 || CONTROL_CHARACTER.test(nameValue) || nameValue.includes("\\"))) {
    throw new ScriptArtifactError("invalid_script_artifact_query", "name must be a bounded safe relative script name");
  }
  let limit = 100;
  if (query.limit !== undefined) {
    if (typeof query.limit !== "string" || !/^\d+$/u.test(query.limit)) {
      throw new ScriptArtifactError("invalid_script_artifact_query", "limit must be an integer from 1 through 100");
    }
    limit = Number(query.limit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new ScriptArtifactError("invalid_script_artifact_query", "limit must be an integer from 1 through 100");
    }
  }
  return {
    missionId: scriptIdentifier(missionId, "missionId"),
    ...(runId ? { runId: scriptIdentifier(runId, "runId") } : {}),
    ...(planId ? { planId: scriptIdentifier(planId, "planId") } : {}),
    ...(stepId ? { stepId: scriptIdentifier(stepId, "stepId") } : {}),
    ...(targetNodeId ? { targetNodeId: scriptIdentifier(targetNodeId, "targetNodeId") } : {}),
    ...(languageResult?.success ? { language: languageResult.data } : {}),
    ...(nameValue ? { name: nameValue.trim() } : {}),
    limit,
  };
}

export function scriptContentHash(source: string): string {
  return createHash("sha256").update(source, "utf8").digest("hex");
}
