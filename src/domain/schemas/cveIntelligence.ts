import type {
  CveApplicability,
  CveApplicabilityDetail,
  CveApplicabilityList,
  CveApplicabilityRecord,
  CveApplicabilityReviewDecision,
  CveApplicabilityReviewDetail,
  CveApplicabilityReviewReceipt,
  CveApplicabilityReviewState,
  CveIntelligenceJson,
  CveSourceKind,
  CveSourceLink,
  KevStatus,
  MissionScopedNvdDetail,
} from "../types/cveIntelligence";

type UnknownRecord = Record<string, unknown>;

const APPLICABILITY = new Set<CveApplicability>([
  "confirmed", "likely", "possible", "not_applicable", "insufficient_evidence",
]);
const SOURCE_KINDS = new Set<CveSourceKind>(["cve_org", "nvd", "mitre", "cisa", "vendor"]);
const KEV_STATES = new Set<KevStatus>(["listed", "not_listed", "unknown"]);
const REVIEW_DECISIONS = new Set<CveApplicabilityReviewDecision>([
  "confirm_applicability", "mark_not_applicable", "request_more_evidence",
]);
const REVIEW_STATES = new Set<CveApplicabilityReviewState>([
  "unreviewed", "confirmed", "not_applicable", "more_evidence_requested",
]);
const REVIEW_RESULTS = new Set<CveApplicabilityReviewReceipt["resultingApplicability"]>([
  "confirmed", "not_applicable", "insufficient_evidence",
]);
const REVIEW_ACTORS = new Set<CveApplicabilityReviewReceipt["actor"]["type"]>([
  "operator", "agent", "worker", "system",
]);
const IDENTIFIER = /^[A-Za-z0-9._:@-]{1,240}$/u;
const CVE_ID = /^CVE-(?:19|20)\d{2}-\d{4,}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const CWE = /^CWE-(?:\d+|NOINFO|OTHER)$/u;
const CVSS_SEVERITY = new Set<NonNullable<MissionScopedNvdDetail["detail"]["strongestCvss"]>["baseSeverity"]>([
  "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN",
]);

function record(value: unknown, label: string): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as UnknownRecord;
}

function exact(value: unknown, label: string, required: readonly string[], optional: readonly string[] = []): UnknownRecord {
  const item = record(value, label);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(item)) {
    if (!allowed.has(key)) throw new Error(`${label} contains unsupported field ${key}`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(item, key)) throw new Error(`${label} is missing ${key}`);
  }
  return item;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function identifier(value: unknown, label: string): string {
  const result = text(value, label);
  if (!IDENTIFIER.test(result)) throw new Error(`${label} must be a stable identifier`);
  return result;
}

function optionalIdentifier(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : identifier(value, label);
}

function optionalText(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : text(value, label);
}

function timestamp(value: unknown, label: string): string {
  const result = text(value, label);
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO timestamp`);
  return result;
}

function optionalTimestamp(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : timestamp(value, label);
}

function boundedRatio(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${label} must be between zero and one`);
  }
  return value;
}

function boundedInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}`);
  }
  return value as number;
}

function sha256(value: unknown, label: string): string {
  const result = text(value, label);
  if (!SHA256.test(result)) throw new Error(`${label} must be a lowercase SHA-256 digest`);
  return result;
}

function literal<T extends string | boolean>(value: unknown, expected: T, label: string): T {
  if (value !== expected) throw new Error(`${label} must be ${String(expected)}`);
  return expected;
}

function optionalRatio(value: unknown, label: string): number | undefined {
  return value === undefined ? undefined : boundedRatio(value, label);
}

function enumValue<T extends string>(value: unknown, allowed: ReadonlySet<T>, label: string): T {
  const result = text(value, label) as T;
  if (!allowed.has(result)) throw new Error(`${label} is invalid`);
  return result;
}

function jsonValue(value: unknown, label: string, seen = new Set<object>(), depth = 0): CveIntelligenceJson {
  if (depth > 16) throw new Error(`${label} exceeds the JSON depth bound`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number`);
    return value;
  }
  if (!value || typeof value !== "object") throw new Error(`${label} is not JSON-safe`);
  if (seen.has(value)) throw new Error(`${label} cannot contain cycles`);
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > 2_000) throw new Error(`${label} contains too many values`);
      return value.map((entry, index) => jsonValue(entry, `${label}[${index}]`, seen, depth + 1));
    }
    const entries = Object.entries(value as UnknownRecord);
    if (entries.length > 2_000) throw new Error(`${label} contains too many fields`);
    const result: Record<string, CveIntelligenceJson> = {};
    for (const [key, entry] of entries) {
      if (["__proto__", "prototype", "constructor"].includes(key) || entry === undefined) {
        throw new Error(`${label} contains an unsafe field`);
      }
      result[key] = jsonValue(entry, `${label}.${key}`, seen, depth + 1);
    }
    return result;
  } finally { seen.delete(value); }
}

function jsonObject(value: unknown, label: string): Readonly<Record<string, CveIntelligenceJson>> {
  const result = jsonValue(value, label);
  if (result === null || Array.isArray(result) || typeof result !== "object") throw new Error(`${label} must be a JSON object`);
  return result as Readonly<Record<string, CveIntelligenceJson>>;
}

function cvssObject(value: unknown): Readonly<Record<string, CveIntelligenceJson>> {
  const result = jsonObject(value, "CVE CVSS");
  if (result.score !== undefined && (
    typeof result.score !== "number"
    || result.score < 0
    || result.score > 10
  )) {
    throw new Error("CVE CVSS score must be between zero and ten");
  }
  if (result.version !== undefined && typeof result.version !== "string") {
    throw new Error("CVE CVSS version must be a string");
  }
  if (result.vector !== undefined && typeof result.vector !== "string") {
    throw new Error("CVE CVSS vector must be a string");
  }
  return result;
}

function authoritativeSource(value: unknown, cveId: string, index: number): CveSourceLink {
  const item = exact(value, `CVE source ${index + 1}`, ["kind", "url", "label"]);
  const kind = enumValue(item.kind, SOURCE_KINDS, `CVE source ${index + 1}.kind`);
  const rawUrl = text(item.url, `CVE source ${index + 1}.url`);
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new Error(`CVE source ${index + 1}.url is malformed`); }
  const host = url.hostname.toLocaleLowerCase("en-US").replace(/^\[|\]$/gu, "");
  const publicVendorHost = host.includes(".") && !(
    host === "localhost"
    || host.endsWith(".localhost")
    || host.endsWith(".local")
    || host.endsWith(".internal")
    || host.endsWith(".lan")
    || host.endsWith(".home")
    || host.endsWith(".test")
    || host === "127.0.0.1"
    || host === "0.0.0.0"
    || host === "::1"
    || /^10\./u.test(host)
    || /^192\.168\./u.test(host)
    || /^172\.(?:1[6-9]|2\d|3[01])\./u.test(host)
    || /^169\.254\./u.test(host)
    || /^(?:fc|fd|fe[89ab])/u.test(host.replaceAll(":", ""))
  );
  const expectedHost = kind === "cve_org"
    ? host === "cve.org" || host === "www.cve.org"
    : kind === "nvd"
      ? host === "nvd.nist.gov"
      : kind === "mitre"
        ? host === "cve.mitre.org" || host === "www.mitre.org" || host.endsWith(".mitre.org")
        : kind === "cisa"
          ? host === "cisa.gov" || host === "www.cisa.gov" || host.endsWith(".cisa.gov")
          : publicVendorHost;
  if (url.protocol !== "https:" || url.username || url.password || !expectedHost) {
    throw new Error(`CVE source ${index + 1}.url is not an authoritative public HTTPS source`);
  }
  let decoded = url.toString();
  try { decoded = decodeURIComponent(decoded); } catch { /* the URL is still structurally valid */ }
  if (kind !== "vendor" && !decoded.toLocaleUpperCase("en-US").includes(cveId)) {
    throw new Error(`CVE source ${index + 1}.url does not reference ${cveId}`);
  }
  return { kind, url: url.toString(), label: text(item.label, `CVE source ${index + 1}.label`) };
}

function parseReviewReceipt(value: unknown): CveApplicabilityReviewReceipt {
  const item = exact(value, "CVE applicability review receipt", [
    "id", "missionId", "runId", "cveApplicabilityId", "version", "decision",
    "previousApplicability", "resultingApplicability", "reason", "actor",
    "expectedRecordUpdatedAt", "auditRecordId", "eventId", "createdAt",
  ]);
  const actor = exact(item.actor, "CVE applicability review actor", ["type", "id"]);
  return {
    id: identifier(item.id, "CVE applicability review receipt ID"),
    missionId: identifier(item.missionId, "CVE applicability review mission ID"),
    runId: identifier(item.runId, "CVE applicability review run ID"),
    cveApplicabilityId: identifier(
      item.cveApplicabilityId,
      "CVE applicability review record ID",
    ),
    version: boundedInteger(
      item.version,
      "CVE applicability review version",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    decision: enumValue(
      item.decision,
      REVIEW_DECISIONS,
      "CVE applicability review decision",
    ),
    previousApplicability: enumValue(
      item.previousApplicability,
      APPLICABILITY,
      "CVE applicability review previous state",
    ),
    resultingApplicability: enumValue(
      item.resultingApplicability,
      REVIEW_RESULTS,
      "CVE applicability review resulting state",
    ),
    reason: text(item.reason, "CVE applicability review reason"),
    actor: {
      type: enumValue(actor.type, REVIEW_ACTORS, "CVE applicability review actor type"),
      id: identifier(actor.id, "CVE applicability review actor ID"),
    },
    expectedRecordUpdatedAt: timestamp(
      item.expectedRecordUpdatedAt,
      "CVE applicability review expected record time",
    ),
    auditRecordId: identifier(
      item.auditRecordId,
      "CVE applicability review audit record ID",
    ),
    eventId: identifier(item.eventId, "CVE applicability review event ID"),
    createdAt: timestamp(item.createdAt, "CVE applicability review time"),
  };
}

function parseRecord(value: unknown): CveApplicabilityRecord {
  const item = exact(value, "CVE applicability record", [
    "id", "missionId", "cveId", "title", "description", "component", "cpeOrPackage",
    "applicability", "confidence", "reasoningSummary", "cvss", "cwe", "sourceLinks",
    "sourceRetrievedAt", "reviewState", "reviewVersion", "createdAt", "updatedAt",
  ], [
    "runId", "assetNodeId", "serviceNodeId", "detectedVersion", "affectedRange", "epss",
    "kevStatus", "exploitMaturity", "publishedAt", "modifiedAt", "sourceVersion",
    "discoveryAgentId", "versionEvidenceId", "latestReview",
  ]);
  const recordId = identifier(item.id, "CVE applicability ID");
  const missionId = identifier(item.missionId, "CVE mission ID");
  const cveId = text(item.cveId, "CVE ID").toLocaleUpperCase("en-US");
  if (!CVE_ID.test(cveId)) throw new Error("CVE ID must use the canonical CVE-YYYY-NNNN form");
  const assetNodeId = optionalIdentifier(item.assetNodeId, "CVE asset node ID");
  const serviceNodeId = optionalIdentifier(item.serviceNodeId, "CVE service node ID");
  const runId = optionalIdentifier(item.runId, "CVE run ID");
  if (!assetNodeId && !serviceNodeId) throw new Error("CVE applicability record has no topology target");
  const applicability = enumValue(item.applicability, APPLICABILITY, "CVE applicability");
  const detectedVersion = optionalText(item.detectedVersion, "CVE detected version");
  const affectedRange = optionalText(item.affectedRange, "CVE affected range");
  const versionEvidenceId = optionalIdentifier(item.versionEvidenceId, "CVE version evidence ID");
  if (["confirmed", "not_applicable"].includes(applicability) && (!detectedVersion || !affectedRange || !versionEvidenceId)) {
    throw new Error(`${applicability} CVE applicability is missing its version comparison evidence`);
  }
  if (!Array.isArray(item.sourceLinks) || item.sourceLinks.length < 1 || item.sourceLinks.length > 25) {
    throw new Error("CVE applicability requires one through 25 authoritative sources");
  }
  const sourceLinks = item.sourceLinks.map((source, index) => authoritativeSource(source, cveId, index));
  if (!sourceLinks.some((source) => source.kind !== "vendor")) {
    throw new Error("CVE applicability requires a non-vendor authoritative source");
  }
  if (new Set(sourceLinks.map((source) => `${source.kind}:${source.url}`)).size !== sourceLinks.length) {
    throw new Error("CVE applicability source links must be unique");
  }
  if (!Array.isArray(item.cwe) || item.cwe.length > 100) throw new Error("CVE CWE list is invalid");
  const cwe = item.cwe.map((entry, index) => {
    const result = text(entry, `CVE CWE ${index + 1}`);
    if (!/^CWE-\d+$/u.test(result)) throw new Error(`CVE CWE ${index + 1} is invalid`);
    return result;
  });
  if (new Set(cwe).size !== cwe.length) throw new Error("CVE CWE values must be unique");
  const epss = optionalRatio(item.epss, "CVE EPSS");
  const exploitMaturity = optionalText(item.exploitMaturity, "CVE exploit maturity");
  const publishedAt = optionalTimestamp(item.publishedAt, "CVE published time");
  const modifiedAt = optionalTimestamp(item.modifiedAt, "CVE modified time");
  if (publishedAt && modifiedAt && Date.parse(modifiedAt) < Date.parse(publishedAt)) {
    throw new Error("CVE modification time cannot precede publication time");
  }
  const sourceVersion = optionalText(item.sourceVersion, "CVE source version");
  const discoveryAgentId = optionalIdentifier(item.discoveryAgentId, "CVE discovery agent ID");
  const reviewState = enumValue(item.reviewState, REVIEW_STATES, "CVE review state");
  const reviewVersion = boundedInteger(
    item.reviewVersion,
    "CVE review version",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const latestReview = item.latestReview === undefined
    ? undefined
    : parseReviewReceipt(item.latestReview);
  if (reviewVersion === 0 && latestReview) {
    throw new Error("An unversioned CVE review cannot have a receipt");
  }
  if (reviewVersion > 0 && (!latestReview || latestReview.version !== reviewVersion)) {
    throw new Error("CVE review projection does not match its latest immutable receipt");
  }
  if (latestReview && (
    latestReview.cveApplicabilityId !== recordId
    || latestReview.missionId !== missionId
    || !runId
    || latestReview.runId !== runId
  )) {
    throw new Error("CVE review receipt is outside its record scope");
  }
  if (reviewState !== "unreviewed" && latestReview?.resultingApplicability !== applicability) {
    throw new Error("CVE review state does not match the canonical applicability");
  }
  return {
    id: recordId,
    missionId,
    ...(runId ? { runId } : {}),
    ...(assetNodeId ? { assetNodeId } : {}),
    ...(serviceNodeId ? { serviceNodeId } : {}),
    cveId,
    title: text(item.title, "CVE title"),
    description: text(item.description, "CVE description"),
    component: text(item.component, "CVE component"),
    ...(detectedVersion ? { detectedVersion } : {}),
    ...(affectedRange ? { affectedRange } : {}),
    cpeOrPackage: jsonObject(item.cpeOrPackage, "CVE CPE or package match"),
    applicability,
    confidence: boundedRatio(item.confidence, "CVE confidence"),
    reasoningSummary: text(item.reasoningSummary, "CVE applicability reasoning"),
    cvss: cvssObject(item.cvss),
    cwe,
    ...(epss === undefined ? {} : { epss }),
    ...(item.kevStatus === undefined ? {} : { kevStatus: enumValue(item.kevStatus, KEV_STATES, "CVE KEV status") }),
    ...(exploitMaturity ? { exploitMaturity } : {}),
    ...(publishedAt ? { publishedAt } : {}),
    ...(modifiedAt ? { modifiedAt } : {}),
    sourceLinks,
    sourceRetrievedAt: timestamp(item.sourceRetrievedAt, "CVE source retrieval time"),
    ...(sourceVersion ? { sourceVersion } : {}),
    ...(discoveryAgentId ? { discoveryAgentId } : {}),
    ...(versionEvidenceId ? { versionEvidenceId } : {}),
    reviewState,
    reviewVersion,
    ...(latestReview ? { latestReview } : {}),
    createdAt: timestamp(item.createdAt, "CVE created time"),
    updatedAt: timestamp(item.updatedAt, "CVE updated time"),
  };
}

export function parseCveApplicabilityList(value: unknown): CveApplicabilityList {
  const root = exact(value, "CVE applicability list", ["schemaVersion", "items"]);
  if (root.schemaVersion !== "2.4") throw new Error("unsupported Ti-Scale schema version");
  if (!Array.isArray(root.items)) throw new Error("CVE applicability items must be an array");
  return { schemaVersion: "2.4", items: root.items.map(parseRecord) };
}

export function parseCveApplicabilityDetail(value: unknown): CveApplicabilityDetail {
  const root = exact(value, "CVE applicability detail", ["schemaVersion", "record"]);
  if (root.schemaVersion !== "2.4") throw new Error("unsupported Ti-Scale schema version");
  return { schemaVersion: "2.4", record: parseRecord(root.record) };
}

export function parseCveApplicabilityReviewDetail(
  value: unknown,
): CveApplicabilityReviewDetail {
  const root = exact(
    value,
    "CVE applicability review detail",
    ["schemaVersion", "record", "receipt"],
  );
  if (root.schemaVersion !== "2.4") throw new Error("unsupported Ti-Scale schema version");
  const parsedRecord = parseRecord(root.record);
  const receipt = parseReviewReceipt(root.receipt);
  if (
    receipt.id !== parsedRecord.latestReview?.id
    || receipt.version !== parsedRecord.reviewVersion
    || JSON.stringify(receipt) !== JSON.stringify(parsedRecord.latestReview)
  ) {
    throw new Error("CVE review response receipt does not match its canonical record");
  }
  return { schemaVersion: "2.4", record: parsedRecord, receipt };
}

/**
 * Accepts only the redacted mission-scoped NVD projection. In particular,
 * `exact` rejects an upstream description body, reference URLs, API URL, or
 * any other unreviewed public payload before React can observe it.
 */
export function parseMissionScopedNvdDetail(value: unknown): MissionScopedNvdDetail {
  const root = exact(value, "mission-scoped NVD detail", [
    "schemaVersion", "summary", "context", "detail", "provenance",
    "targetInteraction", "executionAuthority",
  ]);
  literal(root.schemaVersion, "ti-scale.mission-nvd-detail.v1", "mission-scoped NVD schema version");
  literal(root.targetInteraction, false, "mission-scoped NVD target interaction");
  literal(root.executionAuthority, "none", "mission-scoped NVD execution authority");

  const context = exact(root.context, "mission-scoped NVD context", [
    "missionId", "runId", "stepId", "reviewedCveRef", "applicability", "confidence", "reviewedAt",
  ]);
  const detail = exact(root.detail, "mission-scoped NVD record", [
    "cveId", "weaknesses", "referenceCount", "externalDescription",
  ], ["publishedAt", "lastModifiedAt", "strongestCvss"]);
  const provenance = exact(root.provenance, "mission-scoped NVD provenance", [
    "authority", "api", "recordUrl", "retrievedAt", "invocationId", "connectionId", "toolName",
    "configurationSha256", "capabilityManifestSha256", "inputSha256", "resultSha256", "startedAt",
    "completedAt", "auditRecordId", "redaction",
  ]);
  const externalDescription = exact(detail.externalDescription, "mission-scoped NVD external description", [
    "contentSha256", "classification", "lifecycle", "promptEligible",
  ]);
  const redaction = exact(provenance.redaction, "mission-scoped NVD redaction receipt", [
    "apiUrl", "externalDescriptionText", "externalReferences", "providerErrorBody",
  ]);

  const cveId = text(detail.cveId, "mission-scoped NVD CVE ID").toLocaleUpperCase("en-US");
  if (!CVE_ID.test(cveId)) throw new Error("mission-scoped NVD CVE ID must use the canonical form");
  const publishedAt = optionalTimestamp(detail.publishedAt, "mission-scoped NVD publication time");
  const lastModifiedAt = optionalTimestamp(detail.lastModifiedAt, "mission-scoped NVD modification time");
  if (publishedAt && lastModifiedAt && Date.parse(lastModifiedAt) < Date.parse(publishedAt)) {
    throw new Error("mission-scoped NVD modification time cannot precede publication time");
  }

  let strongestCvss: MissionScopedNvdDetail["detail"]["strongestCvss"];
  if (detail.strongestCvss !== undefined) {
    const score = exact(detail.strongestCvss, "mission-scoped NVD strongest CVSS", [
      "version", "baseScore", "baseSeverity",
    ]);
    if (typeof score.baseScore !== "number" || !Number.isFinite(score.baseScore)
      || score.baseScore < 0 || score.baseScore > 10) {
      throw new Error("mission-scoped NVD CVSS score must be between zero and ten");
    }
    strongestCvss = {
      version: text(score.version, "mission-scoped NVD CVSS version"),
      baseScore: score.baseScore,
      baseSeverity: enumValue(score.baseSeverity, CVSS_SEVERITY, "mission-scoped NVD CVSS severity"),
    };
  }
  if (!Array.isArray(detail.weaknesses) || detail.weaknesses.length > 64) {
    throw new Error("mission-scoped NVD weaknesses must be an array of at most 64 values");
  }
  const weaknesses = detail.weaknesses.map((candidate, index) => {
    const result = text(candidate, `mission-scoped NVD weakness ${index + 1}`);
    if (!CWE.test(result)) throw new Error(`mission-scoped NVD weakness ${index + 1} is invalid`);
    return result;
  });
  if (new Set(weaknesses).size !== weaknesses.length) {
    throw new Error("mission-scoped NVD weaknesses must be unique");
  }

  const rawRecordUrl = text(provenance.recordUrl, "mission-scoped NVD record URL");
  let recordUrl: URL;
  try { recordUrl = new URL(rawRecordUrl); } catch { throw new Error("mission-scoped NVD record URL is malformed"); }
  if (recordUrl.protocol !== "https:" || recordUrl.hostname !== "nvd.nist.gov"
    || recordUrl.username || recordUrl.password
    || recordUrl.pathname !== `/vuln/detail/${cveId}` || recordUrl.search || recordUrl.hash) {
    throw new Error("mission-scoped NVD record URL is not the exact public NVD record");
  }

  const startedAt = timestamp(provenance.startedAt, "mission-scoped NVD invocation start");
  const completedAt = timestamp(provenance.completedAt, "mission-scoped NVD invocation completion");
  if (Date.parse(completedAt) < Date.parse(startedAt)) {
    throw new Error("mission-scoped NVD invocation completion cannot precede its start");
  }

  return {
    schemaVersion: "ti-scale.mission-nvd-detail.v1",
    summary: text(root.summary, "mission-scoped NVD summary"),
    context: {
      missionId: identifier(context.missionId, "mission-scoped NVD mission ID"),
      runId: identifier(context.runId, "mission-scoped NVD run ID"),
      stepId: identifier(context.stepId, "mission-scoped NVD step ID"),
      reviewedCveRef: identifier(context.reviewedCveRef, "mission-scoped NVD reviewed CVE reference"),
      applicability: enumValue(context.applicability, APPLICABILITY, "mission-scoped NVD applicability"),
      confidence: boundedRatio(context.confidence, "mission-scoped NVD confidence"),
      reviewedAt: timestamp(context.reviewedAt, "mission-scoped NVD review time"),
    },
    detail: {
      cveId,
      ...(publishedAt ? { publishedAt } : {}),
      ...(lastModifiedAt ? { lastModifiedAt } : {}),
      ...(strongestCvss ? { strongestCvss } : {}),
      weaknesses,
      referenceCount: boundedInteger(detail.referenceCount, "mission-scoped NVD reference count", 0, 64),
      externalDescription: {
        contentSha256: sha256(externalDescription.contentSha256, "mission-scoped NVD external-description hash"),
        classification: literal(externalDescription.classification, "external_untrusted", "mission-scoped NVD external-description classification"),
        lifecycle: literal(externalDescription.lifecycle, "quarantined", "mission-scoped NVD external-description lifecycle"),
        promptEligible: literal(externalDescription.promptEligible, false, "mission-scoped NVD external-description prompt eligibility"),
      },
    },
    provenance: {
      authority: literal(provenance.authority, "NIST National Vulnerability Database", "mission-scoped NVD authority"),
      api: literal(provenance.api, "NVD API 2.0", "mission-scoped NVD API"),
      recordUrl: recordUrl.toString(),
      retrievedAt: timestamp(provenance.retrievedAt, "mission-scoped NVD retrieval time"),
      invocationId: identifier(provenance.invocationId, "mission-scoped NVD invocation ID"),
      connectionId: identifier(provenance.connectionId, "mission-scoped NVD connection ID"),
      toolName: literal(provenance.toolName, "get_cve_details", "mission-scoped NVD tool name"),
      configurationSha256: sha256(provenance.configurationSha256, "mission-scoped NVD configuration hash"),
      capabilityManifestSha256: sha256(provenance.capabilityManifestSha256, "mission-scoped NVD capability-manifest hash"),
      inputSha256: sha256(provenance.inputSha256, "mission-scoped NVD input hash"),
      resultSha256: sha256(provenance.resultSha256, "mission-scoped NVD result hash"),
      startedAt,
      completedAt,
      auditRecordId: identifier(provenance.auditRecordId, "mission-scoped NVD audit record ID"),
      redaction: {
        apiUrl: literal(redaction.apiUrl, "removed", "mission-scoped NVD API URL redaction"),
        externalDescriptionText: literal(redaction.externalDescriptionText, "quarantined_not_returned", "mission-scoped NVD description redaction"),
        externalReferences: literal(redaction.externalReferences, "count_only", "mission-scoped NVD reference redaction"),
        providerErrorBody: literal(redaction.providerErrorBody, "never_retained", "mission-scoped NVD provider-error redaction"),
      },
    },
    targetInteraction: false,
    executionAuthority: "none",
  };
}

export { parseRecord as parseCveApplicabilityRecord };
