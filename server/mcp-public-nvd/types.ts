import { z } from "zod";

export const PUBLIC_NVD_SERVER_NAME = "ti-scale-public-nvd";
export const PUBLIC_NVD_SERVER_VERSION = "0.1.0";
export const PUBLIC_NVD_TOOL_NAME = "get_cve_details";
export const NVD_API_ORIGIN = "https://services.nvd.nist.gov";
export const NVD_API_PATH = "/rest/json/cves/2.0";
export const NVD_RECORD_ORIGIN = "https://nvd.nist.gov";

export const CVE_ID_PATTERN = /^CVE-(?:1999|2\d{3})-\d{4,19}$/u;

export const CveIdSchema = z.string()
  .min(13)
  .max(29)
  .regex(CVE_ID_PATTERN, "Use an uppercase CVE identifier such as CVE-2021-44228");

export const PublicNvdToolInputSchema = z.object({
  cveId: CveIdSchema.describe("The exact uppercase CVE identifier to look up."),
}).strict();

const CvssMetricSchema = z.object({
  version: z.string().min(1).max(16),
  vector: z.string().min(1).max(512),
  baseScore: z.number().min(0).max(10),
  baseSeverity: z.enum(["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]),
}).strict();

const QuarantinedTextSchema = z.object({
  text: z.string().max(32 * 1024),
  contentSha256: z.string().regex(/^[a-f0-9]{64}$/u),
  classification: z.literal("external_untrusted"),
  lifecycle: z.literal("quarantined"),
  promptEligible: z.literal(false),
  normalization: z.literal("unicode_nfc_control_filtered"),
  reason: z.literal("External NVD text requires local validation before model use"),
}).strict();

export const PublicNvdCveDetailSchema = z.object({
  schemaVersion: z.literal("ti-scale.public-nvd.cve-detail.v1"),
  cveId: CveIdSchema,
  targetInteraction: z.literal(false),
  publishedAt: z.string().datetime().optional(),
  lastModifiedAt: z.string().datetime().optional(),
  description: QuarantinedTextSchema,
  cvss: z.array(CvssMetricSchema).max(16),
  weaknesses: z.array(z.string().regex(/^CWE-(?:\d+|NOINFO|OTHER)$/u)).max(64),
  references: z.array(z.string().url().max(2_048)).max(64),
  trustBoundary: z.object({
    classification: z.literal("external_untrusted"),
    promptUse: z.literal("quarantined"),
    reviewed: z.literal(false),
    appliesTo: z.literal("entire_payload"),
    textFields: z.tuple([
      z.literal("description.text"),
      z.literal("cvss[].version"),
      z.literal("cvss[].vector"),
      z.literal("references[]"),
    ]),
  }).strict(),
  provenance: z.object({
    authority: z.literal("NIST National Vulnerability Database"),
    api: z.literal("NVD API 2.0"),
    apiUrl: z.string().url(),
    recordUrl: z.string().url(),
    retrievedAt: z.string().datetime(),
    httpStatus: z.literal(200),
    sourceType: z.literal("public_vulnerability_intelligence"),
  }).strict(),
}).strict();

export type PublicNvdCveDetail = z.infer<typeof PublicNvdCveDetailSchema>;
export type PublicNvdToolInput = z.infer<typeof PublicNvdToolInputSchema>;

export type PublicNvdErrorCode =
  | "invalid_cve_id"
  | "not_found"
  | "rate_limited"
  | "upstream_unavailable"
  | "upstream_rejected"
  | "request_timeout"
  | "response_too_large"
  | "invalid_response"
  | "network_error";

export class PublicNvdError extends Error {
  constructor(
    readonly code: PublicNvdErrorCode,
    readonly humanMessage: string,
    readonly retryable: boolean,
    readonly retryAfterMs?: number,
  ) {
    super(humanMessage);
    this.name = "PublicNvdError";
  }
}

export interface PublicNvdLookupPort {
  getCveDetails(cveId: string): Promise<PublicNvdCveDetail>;
}
