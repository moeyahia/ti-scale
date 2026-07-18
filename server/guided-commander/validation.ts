import { createHash } from "node:crypto";
import type {
  GuidedCommanderPortResponse,
  GuidedContextDisposition,
  GuidedTextResult,
} from "./types";
import { redactReusableMemorySecrets } from "../memory/ReusableMemorySafety";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$/u;
const FINGERPRINT = /^[a-f0-9]{64}$/iu;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const MAX_RESULT_BYTES = 128 * 1024;
const MAX_NOTE_LENGTH = 4_000;

const ALLOWED_TEXT_MEDIA_TYPES = new Set<GuidedTextResult["mediaType"]>([
  "text/plain",
  "application/json",
  "text/csv",
  "application/xml",
  "text/xml",
]);

const MEMORY_NODE_TYPES = new Set([
  "preference",
  "procedure",
  "tool",
  "tactic",
  "technique",
  "source",
] as const);

const MEMORY_SCOPES = new Set(["mission", "engagement", "global"] as const);
const MEMORY_SENSITIVITIES = new Set(["internal", "private", "restricted"] as const);

export class GuidedCommanderError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly options: {
      readonly humanMessage?: string;
      readonly category?: string;
      readonly remediation?: string;
      readonly retryable?: boolean;
      readonly details?: Readonly<Record<string, unknown>>;
    } = {},
  ) {
    super(message);
    this.name = "GuidedCommanderError";
  }
}

function requiredText(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new GuidedCommanderError(400, "invalid_guided_request", `${label} is required`, {
      humanMessage: `${label} is required.`,
      category: "invalid_input",
    });
  }
  const normalized = value.trim().normalize("NFKC");
  if (normalized.length > maximum) {
    throw new GuidedCommanderError(413, "guided_field_too_large", `${label} exceeds ${maximum} characters`, {
      humanMessage: `${label} is too large.`,
      category: "invalid_input",
    });
  }
  return normalized;
}

function optionalText(value: unknown, label: string, maximum: number): string | undefined {
  if (value === undefined || value === null) return undefined;
  return requiredText(value, label, maximum);
}

function plainObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GuidedCommanderError(400, "invalid_guided_request", "Request body must be an object", {
      category: "invalid_input",
    });
  }
  return value as Record<string, unknown>;
}

export function validatePathId(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value.trim())) {
    throw new GuidedCommanderError(400, "invalid_resource_id", `${label} is invalid`, {
      category: "invalid_input",
    });
  }
  return value.trim();
}

export function validateIdempotencyKey(value: unknown): string {
  if (typeof value !== "string" || !IDEMPOTENCY_KEY.test(value.trim())) {
    throw new GuidedCommanderError(400, "idempotency_key_required", "A valid Idempotency-Key is required", {
      humanMessage: "This action requires a stable submission key so it cannot be recorded twice.",
      category: "invalid_input",
    });
  }
  return value.trim();
}

export interface ContextualActionRequest {
  readonly runId: string;
  readonly stepId: string;
  readonly expectedFingerprint: string;
  readonly note?: string;
}

export function validateContextualActionRequest(value: unknown): ContextualActionRequest {
  const body = plainObject(value);
  const expectedFingerprint = requiredText(body.expectedFingerprint, "expectedFingerprint", 64);
  if (!FINGERPRINT.test(expectedFingerprint)) {
    throw new GuidedCommanderError(400, "invalid_action_fingerprint", "Action fingerprint must be SHA-256", {
      category: "invalid_input",
    });
  }
  const note = optionalText(body.note, "note", MAX_NOTE_LENGTH);
  if (note && redactSensitiveText(note).redactionCount > 0) {
    throw sensitiveInputError("The optional note appears to contain authentication material.");
  }
  return {
    runId: validatePathId(body.runId, "runId"),
    stepId: validatePathId(body.stepId, "stepId"),
    expectedFingerprint: expectedFingerprint.toLowerCase(),
    ...(note ? { note } : {}),
  };
}

export interface InterpretResultRequest extends ContextualActionRequest {
  readonly result: GuidedTextResult & { readonly originalText: string };
}

export function validateInterpretResultRequest(value: unknown): InterpretResultRequest {
  const body = plainObject(value);
  const base = validateContextualActionRequest(body);
  const result = plainObject(body.result);
  const source = result.source;
  if (source !== "paste" && source !== "text_upload") {
    throw new GuidedCommanderError(400, "unsupported_result_source", "Result source is unsupported", {
      humanMessage: "Use pasted text or a text-only upload.",
      category: "invalid_input",
      remediation: "Binary and multipart uploads are not accepted by this endpoint.",
    });
  }
  if (typeof result.mediaType !== "string" || !ALLOWED_TEXT_MEDIA_TYPES.has(result.mediaType as GuidedTextResult["mediaType"])) {
    throw new GuidedCommanderError(415, "unsupported_result_media_type", "Result media type is unsupported", {
      humanMessage: "Only bounded plain text, JSON, CSV, or XML results can be interpreted here.",
      category: "invalid_input",
    });
  }
  if (typeof result.text !== "string" || !result.text.length) {
    throw new GuidedCommanderError(400, "result_text_required", "Result text is required", {
      category: "invalid_input",
    });
  }
  const byteSize = Buffer.byteLength(result.text, "utf8");
  if (byteSize > MAX_RESULT_BYTES) {
    throw new GuidedCommanderError(413, "guided_result_too_large", "Text result exceeds the bounded ingestion limit", {
      humanMessage: `Text results are limited to ${MAX_RESULT_BYTES} bytes.`,
      category: "invalid_input",
      remediation: "Submit a smaller relevant excerpt and retain the full file in the evidence artifact workflow.",
    });
  }
  if (result.byteSize !== undefined && result.byteSize !== byteSize) {
    throw new GuidedCommanderError(400, "result_size_mismatch", "Declared result size does not match its text", {
      category: "invalid_input",
    });
  }
  const fileName = optionalText(result.fileName, "fileName", 240);
  if (fileName && (fileName.includes("/") || fileName.includes("\\") || fileName.includes("\0"))) {
    throw new GuidedCommanderError(400, "invalid_result_filename", "Result filename is unsafe", {
      category: "invalid_input",
    });
  }
  const redacted = redactSensitiveText(result.text);
  return {
    ...base,
    result: {
      source,
      mediaType: result.mediaType as GuidedTextResult["mediaType"],
      ...(fileName ? { fileName } : {}),
      byteSize,
      contentHash: createHash("sha256").update(result.text, "utf8").digest("hex"),
      redactedText: redacted.text,
      redactionCount: redacted.redactionCount,
      originalText: result.text,
    },
  };
}

export interface RememberRequest extends ContextualActionRequest {
  readonly sourceMessageId: string;
  readonly nodeType: "preference" | "procedure" | "tool" | "tactic" | "technique" | "source";
  readonly title: string;
  readonly summary: string;
  readonly content?: string;
  readonly scope: "mission" | "engagement" | "global";
  readonly sensitivity: "internal" | "private" | "restricted";
}

export function validateRememberRequest(value: unknown): RememberRequest {
  const body = plainObject(value);
  const base = validateContextualActionRequest(body);
  if (typeof body.nodeType !== "string" || !MEMORY_NODE_TYPES.has(body.nodeType as RememberRequest["nodeType"])) {
    throw new GuidedCommanderError(400, "invalid_memory_candidate_type", "Memory candidate type is unsupported", {
      category: "invalid_input",
    });
  }
  if (typeof body.scope !== "string" || !MEMORY_SCOPES.has(body.scope as RememberRequest["scope"])) {
    throw new GuidedCommanderError(400, "invalid_memory_scope", "Memory scope is invalid", {
      category: "invalid_input",
    });
  }
  if (typeof body.sensitivity !== "string" || !MEMORY_SENSITIVITIES.has(body.sensitivity as RememberRequest["sensitivity"])) {
    throw new GuidedCommanderError(400, "invalid_memory_sensitivity", "Memory sensitivity is invalid", {
      category: "invalid_input",
    });
  }
  if (body.scope === "global" && body.nodeType !== "preference") {
    throw new GuidedCommanderError(409, "global_operational_memory_denied", "Only explicit preferences may be proposed globally here", {
      humanMessage: "Operational knowledge must remain scoped to this mission or engagement.",
      category: "policy_denied",
    });
  }
  const title = requiredText(body.title, "title", 500);
  const summary = requiredText(body.summary, "summary", 4_000);
  const content = optionalText(body.content, "content", 16_000);
  for (const candidate of [title, summary, content].filter((item): item is string => Boolean(item))) {
    if (redactSensitiveText(candidate).redactionCount > 0) {
      throw sensitiveInputError("Reusable memory cannot contain credentials or authentication material.");
    }
  }
  return {
    ...base,
    sourceMessageId: validatePathId(body.sourceMessageId, "sourceMessageId"),
    nodeType: body.nodeType as RememberRequest["nodeType"],
    title,
    summary,
    ...(content ? { content } : {}),
    scope: body.scope as RememberRequest["scope"],
    sensitivity: body.sensitivity as RememberRequest["sensitivity"],
  };
}

export interface DoNotRememberRequest extends ContextualActionRequest {
  readonly candidateId: string;
  readonly reason: string;
}

export function validateDoNotRememberRequest(value: unknown): DoNotRememberRequest {
  const body = plainObject(value);
  const base = validateContextualActionRequest(body);
  const reason = requiredText(body.reason, "reason", 1_000);
  if (redactSensitiveText(reason).redactionCount > 0) {
    throw sensitiveInputError("The suppression reason appears to contain authentication material.");
  }
  return {
    ...base,
    candidateId: validatePathId(body.candidateId, "candidateId"),
    reason,
  };
}

function sensitiveInputError(humanMessage: string): GuidedCommanderError {
  return new GuidedCommanderError(422, "sensitive_material_not_retained", "Sensitive material was rejected", {
    humanMessage,
    category: "policy_denied",
    remediation: "Remove the secret and reference the protected credential by an opaque identifier instead.",
  });
}

export function redactSensitiveText(source: string): { text: string; redactionCount: number } {
  return redactReusableMemorySecrets(source);
}

function responseText(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", `${label} is invalid`, {
      humanMessage: "The Guided explanation provider returned an invalid response.",
      category: "provider_unavailable",
      remediation: "Retry with a healthy planning-only provider.",
      retryable: true,
    });
  }
  return redactSensitiveText(value.trim()).text;
}

function providerObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", `${label} must be an object`, {
      humanMessage: "The Guided explanation provider returned an invalid response.",
      category: "provider_unavailable",
      remediation: "Retry with a healthy planning-only provider.",
      retryable: true,
    });
  }
  return value as Record<string, unknown>;
}

function validateDisposition(value: unknown, index: number): GuidedContextDisposition {
  const item = providerObject(value, `contextUse[${index}]`);
  const allowed = new Set(["nodeId", "used", "relevanceReason", "influenceSummary", "ignoredReason"]);
  if (Object.keys(item).some((key) => !allowed.has(key))) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", "Context usage included unsupported fields", {
      category: "policy_denied",
    });
  }
  if (typeof item.nodeId !== "string" || !IDENTIFIER.test(item.nodeId.trim())) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", "Context node ID is invalid", {
      category: "provider_unavailable",
      retryable: true,
    });
  }
  const nodeId = item.nodeId.trim();
  if (typeof item.used !== "boolean") {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", "Context disposition is invalid", {
      category: "provider_unavailable",
      retryable: true,
    });
  }
  return {
    nodeId,
    used: item.used,
    relevanceReason: responseText(item.relevanceReason, `contextUse[${index}].relevanceReason`, 1_000),
    ...(item.influenceSummary === undefined
      ? {}
      : { influenceSummary: responseText(item.influenceSummary, `contextUse[${index}].influenceSummary`, 2_000) }),
    ...(item.ignoredReason === undefined
      ? {}
      : { ignoredReason: responseText(item.ignoredReason, `contextUse[${index}].ignoredReason`, 2_000) }),
  };
}

export function validatePortResponse(value: unknown): GuidedCommanderPortResponse {
  const body = providerObject(value, "provider response");
  const allowed = new Set([
    "body",
    "summary",
    "confidence",
    "observations",
    "recommendedNextStep",
    "contextUse",
  ]);
  const unknown = Object.keys(body).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", "Provider response included unsupported capabilities", {
      humanMessage: "The provider attempted to return unsupported Guided Commander fields.",
      category: "policy_denied",
      remediation: "Use a planning-only adapter that returns explanation data, not tool calls or plan mutations.",
    });
  }
  if (typeof body.confidence !== "number" || !Number.isFinite(body.confidence) || body.confidence < 0 || body.confidence > 1) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", "Provider confidence is invalid", {
      category: "provider_unavailable",
      retryable: true,
    });
  }
  if (body.observations !== undefined && (!Array.isArray(body.observations) || body.observations.length > 50)) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", "Provider observations are invalid", {
      category: "provider_unavailable",
      retryable: true,
    });
  }
  if (body.contextUse !== undefined && (!Array.isArray(body.contextUse) || body.contextUse.length > 100)) {
    throw new GuidedCommanderError(502, "invalid_guided_commander_response", "Provider context usage is invalid", {
      category: "provider_unavailable",
      retryable: true,
    });
  }
  return {
    body: responseText(body.body, "body", 16_000),
    summary: responseText(body.summary, "summary", 2_000),
    confidence: body.confidence,
    ...(body.observations === undefined
      ? {}
      : { observations: body.observations.map((item, index) => responseText(item, `observations[${index}]`, 2_000)) }),
    ...(body.recommendedNextStep === undefined
      ? {}
      : { recommendedNextStep: responseText(body.recommendedNextStep, "recommendedNextStep", 4_000) }),
    ...(body.contextUse === undefined
      ? {}
      : { contextUse: body.contextUse.map(validateDisposition) }),
  };
}

export function resultRequestIdentity(request: InterpretResultRequest): Readonly<Record<string, unknown>> {
  return {
    runId: request.runId,
    stepId: request.stepId,
    expectedFingerprint: request.expectedFingerprint,
    note: request.note ?? null,
    result: {
      source: request.result.source,
      mediaType: request.result.mediaType,
      fileName: request.result.fileName ?? null,
      byteSize: request.result.byteSize,
      contentHash: request.result.contentHash,
    },
  };
}

export const GUIDED_TEXT_RESULT_MAX_BYTES = MAX_RESULT_BYTES;
