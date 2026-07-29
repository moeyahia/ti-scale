import { z } from "zod";
import { invalidModelConfiguration } from "./ModelConfigurationError";
import {
  MODEL_ASSIGNMENT_PURPOSES,
  MODEL_PREFERENCE_SCOPE_TYPES,
  type ModelAssignmentPurpose,
  type ModelPreferenceFilters,
  type ModelPreferenceScopeType,
  type PutModelPreferenceInput,
} from "./types";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{8,200}$/u;
const IDENTIFIER = z.string().trim().regex(IDENTIFIER_PATTERN);
const SCOPE_TYPE = z.enum(MODEL_PREFERENCE_SCOPE_TYPES);
const ASSIGNMENT_PURPOSE = z.enum(MODEL_ASSIGNMENT_PURPOSES);
const PUT_BODY = z.object({
  purpose: ASSIGNMENT_PURPOSE.optional(),
  agentId: IDENTIFIER.nullable(),
  primaryConfigurationId: IDENTIFIER,
  fallbackConfigurationId: IDENTIFIER.nullable(),
  expectedVersion: z.number().int().nonnegative(),
  reason: z.string().trim().min(1).max(2_000),
}).strict();

function parse<T>(schema: z.ZodType<T>, value: unknown, code: string): T {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const fields = [...new Set(
    result.error.issues.map((issue) => issue.path.join(".") || "value"),
  )];
  throw invalidModelConfiguration(
    code,
    `Model-configuration validation failed for: ${fields.join(", ")}`,
  );
}
export function modelConfigurationIdentifier(
  value: unknown,
  label: string,
): string {
  const result = IDENTIFIER.safeParse(value);
  if (!result.success) {
    throw invalidModelConfiguration(
      "invalid_model_configuration_identifier",
      `${label} is not a valid stable identifier`,
    );
  }
  return result.data;
}

export function modelPreferenceScopeType(value: unknown): ModelPreferenceScopeType {
  return parse(
    SCOPE_TYPE,
    value,
    "invalid_model_preference_scope_type",
  );
}

export function modelAssignmentPurpose(
  value: unknown,
): ModelAssignmentPurpose {
  if (value === undefined || value === "") return "execution";
  return parse(
    ASSIGNMENT_PURPOSE,
    value,
    "invalid_model_assignment_purpose",
  );
}

export function parsePutModelPreference(
  scopeTypeValue: unknown,
  scopeIdValue: unknown,
  value: unknown,
): PutModelPreferenceInput {
  const scopeType = modelPreferenceScopeType(scopeTypeValue);
  const scopeId = modelConfigurationIdentifier(scopeIdValue, "scopeId");
  const body = parse(PUT_BODY, value, "invalid_model_preference_request");

  if (scopeType === "global") {
    if (scopeId !== "global" || body.agentId !== null) {
      throw invalidModelConfiguration(
        "invalid_global_model_preference_scope",
        "Global model preference must use scopeId 'global' and agentId null",
      );
    }
  } else {
    if (body.agentId === null) {
      throw invalidModelConfiguration(
        "model_preference_agent_required",
        `${scopeType} model preference requires an exact agentId`,
      );
    }
    if (scopeType === "agent" && scopeId !== body.agentId) {
      throw invalidModelConfiguration(
        "agent_model_preference_scope_mismatch",
        "Agent preference scopeId must equal agentId",
      );
    }
  }
  if (body.fallbackConfigurationId === body.primaryConfigurationId) {
    throw invalidModelConfiguration(
      "model_preference_duplicate_fallback",
      "Fallback configuration must differ from the primary configuration",
    );
  }

  return {
    purpose: body.purpose ?? "execution",
    scopeType,
    scopeId,
    agentId: body.agentId,
    primaryConfigurationId: body.primaryConfigurationId,
    fallbackConfigurationId: body.fallbackConfigurationId,
    expectedVersion: body.expectedVersion,
    reason: body.reason,
  };
}

function optionalSingleQuery(
  value: unknown,
  label: string,
): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string") {
    throw invalidModelConfiguration(
      "invalid_model_preference_query",
      `${label} must occur exactly once`,
    );
  }
  return modelConfigurationIdentifier(value, label);
}

export function parseModelPreferenceFilters(
  query: Readonly<Record<string, unknown>>,
): ModelPreferenceFilters {
  const scopeTypeValue = optionalSingleQuery(query.scopeType, "scopeType");
  const purposeValue = optionalSingleQuery(query.purpose, "purpose");
  return {
    ...(purposeValue
      ? { purpose: modelAssignmentPurpose(purposeValue) }
      : {}),
    ...(scopeTypeValue
      ? { scopeType: modelPreferenceScopeType(scopeTypeValue) }
      : {}),
    ...(optionalSingleQuery(query.scopeId, "scopeId") !== undefined
      ? { scopeId: optionalSingleQuery(query.scopeId, "scopeId") }
      : {}),
    ...(optionalSingleQuery(query.agentId, "agentId") !== undefined
      ? { agentId: optionalSingleQuery(query.agentId, "agentId") }
      : {}),
  };
}

export function requiredModelConfigurationIdempotencyKey(
  value: string | undefined,
): string {
  const key = value?.trim();
  if (!key || !IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw invalidModelConfiguration(
      "model_configuration_idempotency_key_required",
      "A valid Idempotency-Key header containing 8-200 safe characters is required",
      "Supply a unique Idempotency-Key and reuse it only for the same preference mutation.",
    );
  }
  return key;
}

export function optionalResolutionIdentifier(
  value: unknown,
  label: string,
): string | undefined {
  return optionalSingleQuery(value, label);
}
