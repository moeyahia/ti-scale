import { z } from "zod";
import { redactSecrets } from "../contracts/redaction";
import type {
  CreatePageCaptureInput,
  PageCaptureCertificateMetadata,
  PageCaptureCursor,
  PageCaptureListFilter,
  PageCaptureSecurityHeader,
  PageCaptureSiteMetadata,
  PageCaptureViewport,
} from "./types";
import { PageCaptureError } from "./types";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{8,200}$/u;
const SECRET_QUERY_KEY = /^(?:access[_-]?token|api[_-]?key|authorization|code|cookie|credential|jwt|password|private[_-]?key|refresh[_-]?token|secret|session|signature|sig|token)$/iu;
const FORBIDDEN_METADATA_HOSTS = new Set([
  "169.254.169.254",
  "100.100.100.200",
  "metadata.google.internal",
  "metadata.azure.internal",
  "instance-data.ec2.internal",
]);
const SECURITY_HEADERS = new Set([
  "cache-control",
  "content-security-policy",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "permissions-policy",
  "referrer-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
]);

const ID = z.string().trim().regex(IDENTIFIER_PATTERN);
const SHA256 = z.string().trim().regex(SHA256_PATTERN);
const TIMESTAMP = z.string().trim().min(1).max(100).refine((value) => Number.isFinite(Date.parse(value)));

const viewportSchema = z.object({
  width: z.number().int().min(1).max(16_384),
  height: z.number().int().min(1).max(16_384),
  deviceScaleFactor: z.number().finite().min(0.25).max(8),
  isMobile: z.boolean(),
  fullPage: z.boolean(),
}).strict();

const artifactReferenceSchema = z.object({
  artifactId: ID,
  sha256: SHA256,
}).strict();

const certificateSchema = z.object({
  protocol: z.string().trim().min(1).max(100).optional(),
  cipher: z.string().trim().min(1).max(240).optional(),
  subjectCommonName: z.string().trim().min(1).max(253).optional(),
  issuerCommonName: z.string().trim().min(1).max(500).optional(),
  sanDnsNames: z.array(z.string().trim().min(1).max(253)).max(100).optional(),
  validFrom: TIMESTAMP.optional(),
  validTo: TIMESTAMP.optional(),
  fingerprintSha256: SHA256.optional(),
  verified: z.boolean().optional(),
}).strict();

const securityHeaderSchema = z.object({
  name: z.string().trim().min(1).max(100),
  value: z.string().trim().min(1).max(4_000),
}).strict();

const siteSchema = z.object({
  contentType: z.string().trim().min(1).max(240).optional(),
  contentLength: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
  language: z.string().trim().min(1).max(100).optional(),
  contentEncoding: z.string().trim().min(1).max(100).optional(),
  serverProduct: z.string().trim().min(1).max(500).optional(),
  technologies: z.array(z.string().trim().min(1).max(240)).max(100).optional(),
  securityHeaders: z.array(securityHeaderSchema).max(50).optional(),
}).strict();

const createBodySchema = z.object({
  runId: ID,
  planId: ID.optional(),
  stepId: ID.optional(),
  assetNodeId: ID.optional(),
  serviceNodeId: ID.optional(),
  url: z.string().trim().min(1).max(2_048),
  responseStatus: z.number().int().min(100).max(599),
  title: z.string().trim().min(1).max(1_000).optional(),
  viewport: viewportSchema,
  screenshot: artifactReferenceSchema,
  fullPageScreenshot: artifactReferenceSchema.optional(),
  contentHash: SHA256,
  certificate: certificateSchema.optional(),
  site: siteSchema.optional(),
  capturedByAgentId: ID,
  captureTool: z.string().trim().min(1).max(240),
  sensitivity: z.enum(["public", "internal", "private", "restricted"]),
  redactionState: z.enum(["not_required", "pending", "redacted", "quarantined"]),
  capturedAt: TIMESTAMP,
  evidenceIds: z.array(ID).max(100).optional(),
  observationIds: z.array(ID).max(100).optional(),
  findingIds: z.array(ID).max(100).optional(),
}).strict();

function validationFailure(code: string, label: string, issues: readonly { readonly path: PropertyKey[] }[]): never {
  const fields = [...new Set(issues.map((issue) => issue.path.join(".") || label))];
  throw new PageCaptureError(code, `${label} failed validation for: ${fields.slice(0, 12).join(", ")}`);
}

function assertNoSecrets(value: string, label: string): string {
  const normalized = value.trim();
  if (redactSecrets(normalized) !== normalized) {
    throw new PageCaptureError(
      "page_capture_sensitive_material_rejected",
      `${label} contains credential-like material and was not retained`,
    );
  }
  return normalized;
}

function unique<T>(values: readonly T[], key: (value: T) => string, label: string): readonly T[] {
  if (new Set(values.map(key)).size !== values.length) {
    throw new PageCaptureError("duplicate_page_capture_values", `${label} must not contain duplicates`);
  }
  return values;
}

export function stablePageCaptureIdentifier(value: unknown, label: string): string {
  const result = ID.safeParse(value);
  if (!result.success) throw new PageCaptureError("invalid_page_capture_identifier", `${label} is invalid`);
  return result.data;
}

export function pageCaptureIdempotencyKey(value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized || !IDEMPOTENCY_KEY_PATTERN.test(normalized)) {
    throw new PageCaptureError(
      "page_capture_idempotency_key_required",
      "A unique Idempotency-Key containing 8-200 safe characters is required",
    );
  }
  return normalized;
}

export function sha256Digest(value: string, label: string): string {
  const normalized = value.trim().toLocaleLowerCase("en-US");
  if (!SHA256_PATTERN.test(normalized)) {
    throw new PageCaptureError("invalid_page_capture_hash", `${label} must be a lowercase SHA-256 digest`);
  }
  return normalized;
}

export function pageCaptureTimestamp(value: string, label: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new PageCaptureError("invalid_page_capture_timestamp", `${label} must be an ISO-8601 timestamp`);
  }
  return new Date(milliseconds).toISOString();
}

/** Normalize a supplied URL without ever dereferencing it. */
export function normalizeAuthorizedHttpUrl(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch {
    throw new PageCaptureError("invalid_page_capture_url", "Capture URL is malformed");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password) {
    throw new PageCaptureError(
      "unsafe_page_capture_url",
      "Capture URL must use HTTP(S) and must not contain embedded credentials",
    );
  }
  if (parsed.hash) {
    throw new PageCaptureError("unsafe_page_capture_url", "Capture URL fragments are not retained; submit the canonical endpoint URL");
  }
  const hostname = parsed.hostname.toLocaleLowerCase("en-US").replace(/^\[|\]$/gu, "");
  if (FORBIDDEN_METADATA_HOSTS.has(hostname)) {
    throw new PageCaptureError("unsafe_page_capture_url", "Cloud instance metadata endpoints cannot be recorded as page captures");
  }
  for (const [key, item] of parsed.searchParams) {
    if (SECRET_QUERY_KEY.test(key) || redactSecrets(item) !== item) {
      throw new PageCaptureError(
        "page_capture_sensitive_url_rejected",
        "Capture URL contains credential-like query material and was not retained",
      );
    }
  }
  const ordered = [...parsed.searchParams.entries()].sort(([leftKey, leftValue], [rightKey, rightValue]) => (
    leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue)
  ));
  parsed.search = "";
  for (const [key, item] of ordered) parsed.searchParams.append(key, item);
  parsed.hostname = hostname;
  const normalized = parsed.toString();
  if (normalized.length > 2_048) throw new PageCaptureError("invalid_page_capture_url", "Capture URL exceeds 2,048 characters");
  return normalized;
}

export function normalizePageCaptureViewport(value: PageCaptureViewport): PageCaptureViewport {
  return {
    width: value.width,
    height: value.height,
    deviceScaleFactor: value.deviceScaleFactor,
    isMobile: value.isMobile,
    fullPage: value.fullPage,
  };
}

export function parsePageCaptureViewport(value: unknown): PageCaptureViewport {
  const result = viewportSchema.safeParse(value);
  if (!result.success) validationFailure("page_capture_data_corrupt", "Stored page capture viewport", result.error.issues);
  return normalizePageCaptureViewport(result.data);
}

export function normalizeCertificateMetadata(
  value: PageCaptureCertificateMetadata | undefined,
): PageCaptureCertificateMetadata {
  if (!value) return {};
  const sanDnsNames = unique(
    (value.sanDnsNames ?? []).map((item) => assertNoSecrets(item, "certificate SAN").toLocaleLowerCase("en-US")),
    (item) => item,
    "Certificate SAN names",
  );
  const validFrom = value.validFrom ? pageCaptureTimestamp(value.validFrom, "certificate.validFrom") : undefined;
  const validTo = value.validTo ? pageCaptureTimestamp(value.validTo, "certificate.validTo") : undefined;
  if (validFrom && validTo && Date.parse(validFrom) > Date.parse(validTo)) {
    throw new PageCaptureError("invalid_page_capture_certificate", "Certificate validFrom must not be after validTo");
  }
  return {
    ...(value.protocol ? { protocol: assertNoSecrets(value.protocol, "certificate protocol") } : {}),
    ...(value.cipher ? { cipher: assertNoSecrets(value.cipher, "certificate cipher") } : {}),
    ...(value.subjectCommonName ? { subjectCommonName: assertNoSecrets(value.subjectCommonName, "certificate subject") } : {}),
    ...(value.issuerCommonName ? { issuerCommonName: assertNoSecrets(value.issuerCommonName, "certificate issuer") } : {}),
    ...(sanDnsNames.length ? { sanDnsNames } : {}),
    ...(validFrom ? { validFrom } : {}),
    ...(validTo ? { validTo } : {}),
    ...(value.fingerprintSha256 ? { fingerprintSha256: sha256Digest(value.fingerprintSha256, "certificate fingerprint") } : {}),
    ...(value.verified === undefined ? {} : { verified: value.verified }),
  };
}

export function parsePageCaptureCertificateMetadata(value: unknown): PageCaptureCertificateMetadata {
  const result = certificateSchema.safeParse(value);
  if (!result.success) validationFailure("page_capture_data_corrupt", "Stored certificate metadata", result.error.issues);
  return normalizeCertificateMetadata(result.data);
}

function normalizeSecurityHeader(header: PageCaptureSecurityHeader): PageCaptureSecurityHeader {
  const name = header.name.trim().toLocaleLowerCase("en-US");
  if (!SECURITY_HEADERS.has(name)) {
    throw new PageCaptureError(
      "unsafe_page_capture_metadata",
      `Response header ${name || "(empty)"} is not permitted in reusable page-capture metadata`,
    );
  }
  return { name, value: assertNoSecrets(header.value, `response header ${name}`) };
}

export function normalizeSiteMetadata(value: PageCaptureSiteMetadata | undefined): PageCaptureSiteMetadata {
  if (!value) return {};
  const technologies = unique(
    (value.technologies ?? []).map((item) => assertNoSecrets(item, "technology label")),
    (item) => item.toLocaleLowerCase("en-US"),
    "Technology labels",
  );
  const securityHeaders = unique(
    (value.securityHeaders ?? []).map(normalizeSecurityHeader),
    (item) => item.name,
    "Security headers",
  );
  return {
    ...(value.contentType ? { contentType: assertNoSecrets(value.contentType, "content type") } : {}),
    ...(value.contentLength === undefined ? {} : { contentLength: value.contentLength }),
    ...(value.language ? { language: assertNoSecrets(value.language, "content language") } : {}),
    ...(value.contentEncoding ? { contentEncoding: assertNoSecrets(value.contentEncoding, "content encoding") } : {}),
    ...(value.serverProduct ? { serverProduct: assertNoSecrets(value.serverProduct, "server product") } : {}),
    ...(technologies.length ? { technologies } : {}),
    ...(securityHeaders.length ? { securityHeaders } : {}),
  };
}

export function parsePageCaptureSiteMetadata(value: unknown): PageCaptureSiteMetadata {
  const result = siteSchema.safeParse(value);
  if (!result.success) validationFailure("page_capture_data_corrupt", "Stored site metadata", result.error.issues);
  return normalizeSiteMetadata(result.data);
}

export function parseCreatePageCaptureInput(missionId: string, value: unknown): CreatePageCaptureInput {
  const result = createBodySchema.safeParse(value);
  if (!result.success) validationFailure("invalid_page_capture_request", "Page capture request", result.error.issues);
  const body = result.data;
  return {
    missionId,
    ...body,
    ...(body.certificate ? { certificate: body.certificate } : {}),
    ...(body.site ? { site: body.site } : {}),
  };
}

export function encodePageCaptureCursor(value: PageCaptureCursor): string {
  return Buffer.from(JSON.stringify([value.capturedAt, value.id]), "utf8").toString("base64url");
}

export function decodePageCaptureCursor(value: string): PageCaptureCursor {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
    if (!Array.isArray(parsed) || parsed.length !== 2) throw new Error("shape");
    return {
      capturedAt: pageCaptureTimestamp(String(parsed[0]), "cursor capturedAt"),
      id: stablePageCaptureIdentifier(parsed[1], "cursor id"),
    };
  } catch (error) {
    if (error instanceof PageCaptureError) throw error;
    throw new PageCaptureError("invalid_page_capture_cursor", "Page capture cursor is malformed");
  }
}

export function parsePageCaptureListFilter(
  missionId: string,
  query: Record<string, unknown>,
): PageCaptureListFilter {
  const allowed = new Set(["runId", "assetNodeId", "serviceNodeId", "redactionState", "cursor", "limit"]);
  for (const key of Object.keys(query)) {
    if (!allowed.has(key)) throw new PageCaptureError("invalid_page_capture_query", `Unsupported page capture query field: ${key}`);
  }
  const one = (value: unknown, label: string): string | undefined => {
    if (value === undefined || value === "") return undefined;
    if (typeof value !== "string") throw new PageCaptureError("invalid_page_capture_query", `${label} must occur exactly once`);
    return value;
  };
  const runIdValue = one(query.runId, "runId");
  const assetNodeIdValue = one(query.assetNodeId, "assetNodeId");
  const serviceNodeIdValue = one(query.serviceNodeId, "serviceNodeId");
  const redactionStateValue = one(query.redactionState, "redactionState");
  const cursorValue = one(query.cursor, "cursor");
  const runId = runIdValue ? stablePageCaptureIdentifier(runIdValue, "runId") : undefined;
  const assetNodeId = assetNodeIdValue ? stablePageCaptureIdentifier(assetNodeIdValue, "assetNodeId") : undefined;
  const serviceNodeId = serviceNodeIdValue ? stablePageCaptureIdentifier(serviceNodeIdValue, "serviceNodeId") : undefined;
  const redactionStates = new Set(["not_required", "pending", "redacted", "quarantined"]);
  if (redactionStateValue && !redactionStates.has(redactionStateValue)) {
    throw new PageCaptureError("invalid_page_capture_query", "redactionState is unsupported");
  }
  let limit = 50;
  const limitValue = one(query.limit, "limit");
  if (limitValue !== undefined) {
    if (!/^\d+$/u.test(limitValue)) throw new PageCaptureError("invalid_page_capture_query", "limit must be an integer from 1 through 100");
    limit = Number(limitValue);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new PageCaptureError("invalid_page_capture_query", "limit must be an integer from 1 through 100");
    }
  }
  return {
    missionId,
    ...(runId ? { runId } : {}),
    ...(assetNodeId ? { assetNodeId } : {}),
    ...(serviceNodeId ? { serviceNodeId } : {}),
    ...(redactionStateValue ? { redactionState: redactionStateValue as PageCaptureListFilter["redactionState"] } : {}),
    ...(cursorValue ? { cursor: decodePageCaptureCursor(cursorValue) } : {}),
    limit,
  };
}
