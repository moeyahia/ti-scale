import type {
  CveApplicability,
  CveApplicabilityDetail,
  CveApplicabilityList,
  CveApplicabilityRecord,
  CveIntelligenceJson,
  CveSourceKind,
  CveSourceLink,
  KevStatus,
} from "../types/cveIntelligence";

type UnknownRecord = Record<string, unknown>;

const APPLICABILITY = new Set<CveApplicability>([
  "confirmed", "likely", "possible", "not_applicable", "insufficient_evidence",
]);
const SOURCE_KINDS = new Set<CveSourceKind>(["cve_org", "nvd", "mitre", "cisa", "vendor"]);
const KEV_STATES = new Set<KevStatus>(["listed", "not_listed", "unknown"]);
const IDENTIFIER = /^[A-Za-z0-9._:@-]{1,240}$/u;
const CVE_ID = /^CVE-(?:19|20)\d{2}-\d{4,}$/u;

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

function parseRecord(value: unknown): CveApplicabilityRecord {
  const item = exact(value, "CVE applicability record", [
    "id", "missionId", "cveId", "title", "description", "component", "cpeOrPackage",
    "applicability", "confidence", "reasoningSummary", "cvss", "cwe", "sourceLinks",
    "sourceRetrievedAt", "createdAt", "updatedAt",
  ], [
    "runId", "assetNodeId", "serviceNodeId", "detectedVersion", "affectedRange", "epss",
    "kevStatus", "exploitMaturity", "publishedAt", "modifiedAt", "sourceVersion",
    "discoveryAgentId", "versionEvidenceId",
  ]);
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
  return {
    id: identifier(item.id, "CVE applicability ID"),
    missionId: identifier(item.missionId, "CVE mission ID"),
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

export { parseRecord as parseCveApplicabilityRecord };
