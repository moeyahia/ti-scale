import type { OperationalSensitivity } from "../types/operationalTruth";
import type { PageCaptureArtifactProjection, PageCaptureDetail, PageCaptureList, PageCaptureRecord, PageCaptureRedactionState } from "../types/pageCaptures";

type UnknownRecord = Record<string, unknown>;
const SENSITIVITIES = new Set<OperationalSensitivity>(["public", "internal", "private", "restricted"]);
const REDACTIONS = new Set<PageCaptureRedactionState>(["not_required", "pending", "redacted", "quarantined"]);
const SHA256 = /^[a-f0-9]{64}$/u;

function exact(value: unknown, label: string, required: readonly string[], optional: readonly string[] = []): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const item = value as UnknownRecord; const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(item)) if (!allowed.has(key)) throw new Error(`${label} contains unsupported field ${key}`);
  for (const key of required) if (!Object.prototype.hasOwnProperty.call(item, key)) throw new Error(`${label} is missing ${key}`);
  return item;
}
function text(value: unknown, label: string): string { if (typeof value !== "string" || !value.trim() || value.length > 100_000) throw new Error(`${label} must be a bounded string`); return value; }
function optionalText(value: unknown, label: string): string | undefined { return value === undefined ? undefined : text(value, label); }
function id(value: unknown, label: string): string { const result = text(value, label); if (result.length > 240 || /[\u0000-\u001f\u007f]/u.test(result)) throw new Error(`${label} is invalid`); return result; }
function optionalId(value: unknown, label: string): string | undefined { return value === undefined ? undefined : id(value, label); }
function integer(value: unknown, label: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number { if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) throw new Error(`${label} is out of range`); return value as number; }
function finite(value: unknown, label: string, minimum: number, maximum: number): number { if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum) throw new Error(`${label} is out of range`); return value; }
function bool(value: unknown, label: string): boolean { if (typeof value !== "boolean") throw new Error(`${label} must be boolean`); return value; }
function hash(value: unknown, label: string): string { const result = text(value, label); if (!SHA256.test(result)) throw new Error(`${label} must be a lowercase SHA-256 digest`); return result; }
function timestamp(value: unknown, label: string): string { const result = text(value, label); if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO timestamp`); return result; }
function enumValue<T extends string>(value: unknown, allowed: ReadonlySet<T>, label: string): T { const result = text(value, label) as T; if (!allowed.has(result)) throw new Error(`${label} is invalid`); return result; }
function ids(value: unknown, label: string): readonly string[] { if (!Array.isArray(value) || value.length > 1_000) throw new Error(`${label} must be a bounded array`); const result = value.map((entry, index) => id(entry, `${label}[${index}]`)); if (new Set(result).size !== result.length) throw new Error(`${label} must not contain duplicates`); return result; }
function texts(value: unknown, label: string): readonly string[] { if (!Array.isArray(value) || value.length > 1_000) throw new Error(`${label} must be a bounded array`); const result = value.map((entry, index) => text(entry, `${label}[${index}]`)); if (new Set(result).size !== result.length) throw new Error(`${label} must not contain duplicates`); return result; }

function artifact(value: unknown, label: string): PageCaptureArtifactProjection {
  const item = exact(value, label, ["artifactId", "contentHash", "mediaType", "byteSize"]);
  const mediaType = text(item.mediaType, `${label}.mediaType`);
  if (!mediaType.startsWith("image/")) throw new Error(`${label}.mediaType must be an image type`);
  return { artifactId: id(item.artifactId, `${label}.artifactId`), contentHash: hash(item.contentHash, `${label}.contentHash`), mediaType, byteSize: integer(item.byteSize, `${label}.byteSize`, 1) };
}

function record(value: unknown): PageCaptureRecord {
  const item = exact(value, "page capture", ["id", "missionId", "normalizedUrl", "viewport", "contentHash", "certificate", "site", "related", "captureTool", "sensitivity", "redactionState", "capturedAt", "createdAt", "gallery"], ["runId", "planId", "stepId", "stepTitle", "assetNodeId", "assetLabel", "serviceNodeId", "serviceLabel", "responseStatus", "title", "screenshot", "fullPageScreenshot", "screenshotHash", "fullPageScreenshotHash", "capturedByAgentId", "capturedByAgentName"]);
  const normalizedUrl = text(item.normalizedUrl, "capture URL");
  let url: URL; try { url = new URL(normalizedUrl); } catch { throw new Error("capture URL is malformed"); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("capture URL must be an HTTP(S) URL without credentials");
  const viewport = exact(item.viewport, "capture viewport", ["width", "height", "deviceScaleFactor", "isMobile", "fullPage"]);
  const certificate = exact(item.certificate, "capture certificate", [], ["protocol", "cipher", "subjectCommonName", "issuerCommonName", "sanDnsNames", "validFrom", "validTo", "fingerprintSha256", "verified"]);
  const site = exact(item.site, "capture site metadata", [], ["contentType", "contentLength", "language", "contentEncoding", "serverProduct", "technologies", "securityHeaders"]);
  const related = exact(item.related, "capture links", ["evidenceIds", "observationIds", "findingIds"]);
  const gallery = exact(item.gallery, "capture gallery", ["label", "previewArtifactId", "fullPageArtifactId", "previewAvailable", "redactionState"]);
  const screenshot = item.screenshot === undefined ? undefined : artifact(item.screenshot, "capture screenshot");
  const fullPageScreenshot = item.fullPageScreenshot === undefined ? undefined : artifact(item.fullPageScreenshot, "capture full-page screenshot");
  const redactionState = enumValue(item.redactionState, REDACTIONS, "capture redaction state");
  const galleryRedaction = enumValue(gallery.redactionState, REDACTIONS, "gallery redaction state");
  const previewArtifactId = gallery.previewArtifactId === null ? null : id(gallery.previewArtifactId, "gallery preview artifact ID");
  const fullPageArtifactId = gallery.fullPageArtifactId === null ? null : id(gallery.fullPageArtifactId, "gallery full-page artifact ID");
  const previewAvailable = bool(gallery.previewAvailable, "gallery preview availability");
  const visible = redactionState === "not_required" || redactionState === "redacted";
  if (galleryRedaction !== redactionState || previewAvailable !== (visible && Boolean(screenshot)) || (previewAvailable ? previewArtifactId !== screenshot?.artifactId : previewArtifactId !== null)) throw new Error("capture gallery projection is inconsistent with redaction and artifact state");
  if (fullPageArtifactId !== (visible && fullPageScreenshot ? fullPageScreenshot.artifactId : null)) throw new Error("capture full-page gallery projection is inconsistent");
  if (item.screenshotHash !== undefined && (!screenshot || hash(item.screenshotHash, "capture screenshot hash") !== screenshot.contentHash)) throw new Error("capture screenshot hash does not match its artifact");
  if (item.fullPageScreenshotHash !== undefined && (!fullPageScreenshot || hash(item.fullPageScreenshotHash, "capture full-page hash") !== fullPageScreenshot.contentHash)) throw new Error("capture full-page hash does not match its artifact");
  if (site.securityHeaders !== undefined && (!Array.isArray(site.securityHeaders) || site.securityHeaders.length > 200)) throw new Error("capture security headers must be a bounded array");
  const securityHeaders = site.securityHeaders === undefined ? undefined : site.securityHeaders.map((candidate, index) => {
    const header = exact(candidate, `capture security header ${index + 1}`, ["name", "value"]);
    return { name: text(header.name, `capture security header ${index + 1}.name`), value: text(header.value, `capture security header ${index + 1}.value`) };
  });
  return {
    id: id(item.id, "capture ID"), missionId: id(item.missionId, "capture mission ID"),
    ...(optionalId(item.runId, "capture run ID") ? { runId: optionalId(item.runId, "capture run ID") } : {}),
    ...(optionalId(item.planId, "capture plan ID") ? { planId: optionalId(item.planId, "capture plan ID") } : {}),
    ...(optionalId(item.stepId, "capture step ID") ? { stepId: optionalId(item.stepId, "capture step ID") } : {}),
    ...(optionalText(item.stepTitle, "capture step title") ? { stepTitle: optionalText(item.stepTitle, "capture step title") } : {}),
    ...(optionalId(item.assetNodeId, "capture asset ID") ? { assetNodeId: optionalId(item.assetNodeId, "capture asset ID") } : {}),
    ...(optionalText(item.assetLabel, "capture asset label") ? { assetLabel: optionalText(item.assetLabel, "capture asset label") } : {}),
    ...(optionalId(item.serviceNodeId, "capture service ID") ? { serviceNodeId: optionalId(item.serviceNodeId, "capture service ID") } : {}),
    ...(optionalText(item.serviceLabel, "capture service label") ? { serviceLabel: optionalText(item.serviceLabel, "capture service label") } : {}),
    normalizedUrl, ...(item.responseStatus === undefined ? {} : { responseStatus: integer(item.responseStatus, "capture response status", 100, 599) }),
    ...(optionalText(item.title, "capture title") ? { title: optionalText(item.title, "capture title") } : {}),
    viewport: { width: integer(viewport.width, "viewport width", 1, 16_384), height: integer(viewport.height, "viewport height", 1, 16_384), deviceScaleFactor: finite(viewport.deviceScaleFactor, "viewport device scale", 0.1, 10), isMobile: bool(viewport.isMobile, "viewport mobile state"), fullPage: bool(viewport.fullPage, "viewport full-page state") },
    ...(screenshot ? { screenshot } : {}), ...(fullPageScreenshot ? { fullPageScreenshot } : {}), contentHash: hash(item.contentHash, "capture content hash"),
    ...(item.screenshotHash === undefined ? {} : { screenshotHash: hash(item.screenshotHash, "capture screenshot hash") }), ...(item.fullPageScreenshotHash === undefined ? {} : { fullPageScreenshotHash: hash(item.fullPageScreenshotHash, "capture full-page hash") }),
    certificate: {
      ...(optionalText(certificate.protocol, "certificate protocol") ? { protocol: optionalText(certificate.protocol, "certificate protocol") } : {}), ...(optionalText(certificate.cipher, "certificate cipher") ? { cipher: optionalText(certificate.cipher, "certificate cipher") } : {}),
      ...(optionalText(certificate.subjectCommonName, "certificate subject") ? { subjectCommonName: optionalText(certificate.subjectCommonName, "certificate subject") } : {}), ...(optionalText(certificate.issuerCommonName, "certificate issuer") ? { issuerCommonName: optionalText(certificate.issuerCommonName, "certificate issuer") } : {}),
      ...(certificate.sanDnsNames === undefined ? {} : { sanDnsNames: texts(certificate.sanDnsNames, "certificate SAN names") }), ...(certificate.validFrom === undefined ? {} : { validFrom: timestamp(certificate.validFrom, "certificate valid-from time") }), ...(certificate.validTo === undefined ? {} : { validTo: timestamp(certificate.validTo, "certificate valid-to time") }),
      ...(certificate.fingerprintSha256 === undefined ? {} : { fingerprintSha256: hash(certificate.fingerprintSha256, "certificate fingerprint") }), ...(certificate.verified === undefined ? {} : { verified: bool(certificate.verified, "certificate verified state") }),
    },
    site: {
      ...(optionalText(site.contentType, "site content type") ? { contentType: optionalText(site.contentType, "site content type") } : {}), ...(site.contentLength === undefined ? {} : { contentLength: integer(site.contentLength, "site content length") }),
      ...(optionalText(site.language, "site language") ? { language: optionalText(site.language, "site language") } : {}), ...(optionalText(site.contentEncoding, "site content encoding") ? { contentEncoding: optionalText(site.contentEncoding, "site content encoding") } : {}),
      ...(optionalText(site.serverProduct, "site server product") ? { serverProduct: optionalText(site.serverProduct, "site server product") } : {}), ...(site.technologies === undefined ? {} : { technologies: texts(site.technologies, "site technologies") }), ...(securityHeaders ? { securityHeaders } : {}),
    },
    related: { evidenceIds: ids(related.evidenceIds, "capture evidence IDs"), observationIds: ids(related.observationIds, "capture observation IDs"), findingIds: ids(related.findingIds, "capture finding IDs") },
    ...(optionalId(item.capturedByAgentId, "capture agent ID") ? { capturedByAgentId: optionalId(item.capturedByAgentId, "capture agent ID") } : {}), ...(optionalText(item.capturedByAgentName, "capture agent name") ? { capturedByAgentName: optionalText(item.capturedByAgentName, "capture agent name") } : {}),
    captureTool: text(item.captureTool, "capture tool"), sensitivity: enumValue(item.sensitivity, SENSITIVITIES, "capture sensitivity"), redactionState,
    capturedAt: timestamp(item.capturedAt, "capture acquired time"), createdAt: timestamp(item.createdAt, "capture created time"),
    gallery: { label: text(gallery.label, "gallery label"), previewArtifactId, fullPageArtifactId, previewAvailable, redactionState },
  };
}

export function parsePageCaptureList(value: unknown): PageCaptureList {
  const root = exact(value, "page-capture list", ["schemaVersion", "items"], ["nextCursor"]);
  if (root.schemaVersion !== "2.4") throw new Error("unsupported page-capture schema version");
  if (!Array.isArray(root.items) || root.items.length > 100) throw new Error("page-capture list must contain at most 100 records");
  return { schemaVersion: "2.4", items: root.items.map(record), ...(root.nextCursor === undefined ? {} : { nextCursor: text(root.nextCursor, "page-capture cursor") }) };
}

export function parsePageCaptureDetail(value: unknown): PageCaptureDetail {
  const root = exact(value, "page-capture detail", ["schemaVersion", "record"]);
  if (root.schemaVersion !== "2.4") throw new Error("unsupported page-capture schema version");
  return { schemaVersion: "2.4", record: record(root.record) };
}
