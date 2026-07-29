import { isIP } from "node:net";
import { redactSecrets } from "../contracts/redaction";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import type { OperationalActor, Sensitivity } from "../intelligence-v24/types";
import { PageCaptureRepository, type PersistPageCaptureInput } from "./PageCaptureRepository";
import type {
  CreatePageCaptureInput,
  PageCaptureCertificateMetadata,
  PageCaptureListFilter,
  PageCaptureListPage,
  PageCaptureRecord,
  PageCaptureRelatedRecords,
  PageCaptureSiteMetadata,
} from "./types";
import { PageCaptureError } from "./types";
import {
  encodePageCaptureCursor,
  normalizeAuthorizedHttpUrl,
  normalizeCertificateMetadata,
  normalizePageCaptureViewport,
  normalizeSiteMetadata,
  pageCaptureTimestamp,
  sha256Digest,
  stablePageCaptureIdentifier,
} from "./validation";

const ASSET_NODE_TYPES = new Set(["asset", "host", "network_device", "cloud_asset", "container", "cluster"]);
const SERVICE_NODE_TYPES = new Set(["service", "application", "website", "web_application", "endpoint"]);
const SCREENSHOT_ARTIFACT_TYPES = new Set(["screenshot", "page_capture", "web_page_capture", "full_page_capture"]);
const SCREENSHOT_MEDIA_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/avif"]);
const CAPTURE_TOOL = /^[A-Za-z0-9._:/-]{1,240}$/u;
const DNS_NAME = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu;
const SENSITIVITY_RANK: Readonly<Record<Sensitivity, number>> = {
  public: 0,
  internal: 1,
  private: 2,
  restricted: 3,
};

interface MissionRow {
  readonly authorization_status: string;
}

interface RunRow {
  readonly mission_id: string;
}

interface TargetRow {
  readonly target_type: string;
  readonly disposition: "allowed" | "prohibited";
  readonly normalized_target: string;
}

interface StepRow {
  readonly run_id: string;
  readonly plan_id: string;
}

interface TopologyRow {
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly node_type: string;
  readonly scope_status: string;
}

interface ArtifactRow {
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly artifact_type: string;
  readonly content_hash: string;
  readonly byte_size: number;
  readonly media_type: string | null;
  readonly sensitivity: Sensitivity;
}

interface LinkedRecordRow {
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id?: string | null;
  readonly asset_id?: string | null;
  readonly sensitivity?: Sensitivity;
}

interface AgentRow {
  readonly id: string;
}

function safeText(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(normalized)) {
    throw new PageCaptureError("invalid_page_capture_input", `${label} must contain 1-${maximum} safe characters`);
  }
  if (redactSecrets(normalized) !== normalized) {
    throw new PageCaptureError("page_capture_sensitive_material_rejected", `${label} contains credential-like material and was not retained`);
  }
  return normalized;
}

function ipv4Number(value: string): number | undefined {
  if (isIP(value) !== 4) return undefined;
  return value.split(".").reduce((total, item) => total * 256 + Number(item), 0) >>> 0;
}

function ipv4CidrContains(cidr: string, hostname: string): boolean {
  const [networkValue, prefixValue, extra] = cidr.split("/");
  if (!networkValue || !prefixValue || extra !== undefined || !/^\d+$/u.test(prefixValue)) return false;
  const network = ipv4Number(networkValue);
  const address = ipv4Number(hostname);
  const prefix = Number(prefixValue);
  if (network === undefined || address === undefined || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffff_ffff << (32 - prefix)) >>> 0;
  return (network & mask) === (address & mask);
}

function globMatches(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/gu, "\\$&").replaceAll("*", ".*").replaceAll("?", ".");
  try { return new RegExp(`^${escaped}$`, "iu").test(value); } catch { return false; }
}

function pathContains(parent: string, child: string): boolean {
  if (parent === "/") return true;
  const root = parent.endsWith("/") ? parent : `${parent}/`;
  return child === parent || child.startsWith(root);
}

function targetMatches(target: TargetRow, captureUrl: URL): boolean {
  const normalized = target.normalized_target.trim();
  if (target.target_type === "url" || /^https?:\/\//iu.test(normalized)) {
    let targetUrl: URL;
    try { targetUrl = new URL(normalized); } catch { return false; }
    if (targetUrl.protocol !== captureUrl.protocol || targetUrl.origin !== captureUrl.origin) return false;
    if (!pathContains(targetUrl.pathname, captureUrl.pathname)) return false;
    return !targetUrl.search || targetUrl.search === captureUrl.search;
  }
  const lower = normalized.toLocaleLowerCase("en-US");
  if (target.target_type === "cidr") return ipv4CidrContains(lower, captureUrl.hostname);
  if (target.target_type === "pattern") {
    return globMatches(lower, captureUrl.hostname.toLocaleLowerCase("en-US")) || globMatches(lower, captureUrl.toString());
  }
  return lower.replace(/^\[|\]$/gu, "") === captureUrl.hostname.toLocaleLowerCase("en-US").replace(/^\[|\]$/gu, "");
}

function sensitivityCovers(container: Sensitivity, linked: Sensitivity): boolean {
  return SENSITIVITY_RANK[container] >= SENSITIVITY_RANK[linked];
}

function semanticEndpoint(normalizedUrl: string): string {
  const url = new URL(normalizedUrl);
  url.search = "";
  return url.toString();
}

function uniqueIds(values: readonly string[] | undefined, label: string): readonly string[] {
  const normalized = (values ?? []).map((item) => stablePageCaptureIdentifier(item, label));
  if (new Set(normalized).size !== normalized.length) {
    throw new PageCaptureError("duplicate_page_capture_links", `${label} must not contain duplicates`);
  }
  return normalized;
}

/**
 * Validates and records externally supplied authorized page-capture results.
 * This service intentionally has no network or browser dependency.
 */
export class PageCaptureService {
  readonly repository: PageCaptureRepository;
  private readonly events: EventRepository;
  private readonly audit: AuditTrailWriter;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.repository = new PageCaptureRepository(database);
    this.events = new EventRepository(database);
    this.audit = new AuditTrailWriter(database);
  }

  get(missionId: string, captureId: string): PageCaptureRecord {
    const normalizedMissionId = stablePageCaptureIdentifier(missionId, "missionId");
    this.assertMission(normalizedMissionId);
    const record = this.repository.get(stablePageCaptureIdentifier(captureId, "captureId"));
    if (record.missionId !== normalizedMissionId) {
      throw new PageCaptureError("page_capture_not_found", "Page capture was not found in this mission");
    }
    return record;
  }

  list(filter: PageCaptureListFilter): PageCaptureListPage {
    const missionId = stablePageCaptureIdentifier(filter.missionId, "missionId");
    this.assertMission(missionId);
    if (filter.runId) this.assertRun(missionId, filter.runId);
    if (filter.assetNodeId) this.assertNode(missionId, filter.runId, filter.assetNodeId, "asset");
    if (filter.serviceNodeId) this.assertNode(missionId, filter.runId, filter.serviceNodeId, "service");
    const limit = Math.min(Math.max(filter.limit ?? 50, 1), 100);
    const records = this.repository.list({ ...filter, missionId, limit: limit + 1 });
    const items = records.slice(0, limit);
    const last = items.at(-1);
    return {
      items,
      ...(records.length > limit && last
        ? { nextCursor: encodePageCaptureCursor({ capturedAt: last.capturedAt, id: last.id }) }
        : {}),
    };
  }

  create(raw: CreatePageCaptureInput, actor: OperationalActor): PageCaptureRecord {
    return inImmediateTransaction(this.database, () => {
      const input = this.validate(raw, actor);
      const duplicate = this.repository.findCanonical(input.missionId, input.normalizedUrl, input.contentHash);
      if (duplicate) {
        throw new PageCaptureError(
          "page_capture_already_exists",
          "An immutable capture with this mission, URL, and content hash already exists",
        );
      }
      const now = this.clock().toISOString();
      const result = this.repository.insert(input, now);
      const endpoint = semanticEndpoint(result.normalizedUrl);
      this.audit.append({
        missionId: result.missionId,
        runId: result.runId,
        actor,
        action: "page_capture.created",
        resourceType: "page_capture",
        resourceId: result.id,
        reason: "Recorded a supplied authorized web-page capture with immutable artifact provenance",
        details: {
          endpoint,
          responseStatus: result.responseStatus ?? null,
          contentHash: result.contentHash,
          screenshotArtifactId: result.screenshot?.artifactId ?? null,
          fullPageArtifactId: result.fullPageScreenshot?.artifactId ?? null,
          assetNodeId: result.assetNodeId ?? null,
          serviceNodeId: result.serviceNodeId ?? null,
          stepId: result.stepId ?? null,
          redactionState: result.redactionState,
          relatedCounts: {
            evidence: result.related.evidenceIds.length,
            observations: result.related.observationIds.length,
            findings: result.related.findingIds.length,
          },
        },
        occurredAt: now,
      });
      this.events.append({
        missionId: result.missionId,
        runId: result.runId!,
        eventType: "intelligence.page_capture.created",
        occurredAt: now,
        actorType: actor.type,
        actorId: actor.id,
        summary: `${actor.id} recorded an authorized page capture for ${new URL(result.normalizedUrl).hostname} (${result.responseStatus ?? "status unknown"}).`,
        payload: {
          captureId: result.id,
          endpoint,
          responseStatus: result.responseStatus ?? null,
          assetNodeId: result.assetNodeId ?? null,
          serviceNodeId: result.serviceNodeId ?? null,
          stepId: result.stepId ?? null,
          evidenceCount: result.related.evidenceIds.length,
          observationCount: result.related.observationIds.length,
          findingCount: result.related.findingIds.length,
          redactionState: result.redactionState,
        },
        schemaVersion: 1,
        sensitivity: result.sensitivity,
        redaction: { state: result.redactionState },
        outboxTopic: "intelligence.page-captures",
      });
      return result;
    });
  }

  private validate(raw: CreatePageCaptureInput, actor: OperationalActor): PersistPageCaptureInput {
    const missionId = stablePageCaptureIdentifier(raw.missionId, "missionId");
    const runId = stablePageCaptureIdentifier(raw.runId, "runId");
    const planId = raw.planId ? stablePageCaptureIdentifier(raw.planId, "planId") : undefined;
    const stepId = raw.stepId ? stablePageCaptureIdentifier(raw.stepId, "stepId") : undefined;
    const assetNodeId = raw.assetNodeId ? stablePageCaptureIdentifier(raw.assetNodeId, "assetNodeId") : undefined;
    const serviceNodeId = raw.serviceNodeId ? stablePageCaptureIdentifier(raw.serviceNodeId, "serviceNodeId") : undefined;
    const capturedByAgentId = stablePageCaptureIdentifier(raw.capturedByAgentId, "capturedByAgentId");
    const mission = this.assertMission(missionId);
    if (mission.authorization_status !== "verified") {
      throw new PageCaptureError(
        "page_capture_authorization_unverified",
        "Mission authorization must be verified before a page capture can be recorded",
      );
    }
    this.assertRun(missionId, runId);
    if (planId && !stepId) {
      throw new PageCaptureError("invalid_page_capture_plan_scope", "planId may only be supplied with its plan step");
    }
    if (stepId && !planId) {
      throw new PageCaptureError("invalid_page_capture_plan_scope", "planId is required when stepId is supplied");
    }
    if (stepId) this.assertStep(runId, planId, stepId);
    if (!assetNodeId && !serviceNodeId) {
      throw new PageCaptureError("page_capture_target_required", "A page capture must reference an authorized asset or service node");
    }
    if (assetNodeId) this.assertNode(missionId, runId, assetNodeId, "asset");
    if (serviceNodeId) this.assertNode(missionId, runId, serviceNodeId, "service");

    const normalizedUrl = normalizeAuthorizedHttpUrl(raw.url);
    this.assertUrlAuthorized(missionId, normalizedUrl);
    const url = new URL(normalizedUrl);
    const certificate = normalizeCertificateMetadata(raw.certificate);
    if (url.protocol === "http:" && Object.keys(certificate).length > 0) {
      throw new PageCaptureError("invalid_page_capture_certificate", "HTTP captures cannot include TLS certificate metadata");
    }
    for (const san of certificate.sanDnsNames ?? []) {
      if (!DNS_NAME.test(san)) throw new PageCaptureError("invalid_page_capture_certificate", `Certificate SAN is not a valid DNS name: ${san}`);
    }
    const site = normalizeSiteMetadata(raw.site);
    const title = raw.title ? safeText(raw.title, "title", 1_000) : undefined;
    const captureTool = safeText(raw.captureTool, "captureTool", 240);
    if (!CAPTURE_TOOL.test(captureTool)) {
      throw new PageCaptureError("invalid_page_capture_tool", "captureTool must be a stable tool identifier, not a command line");
    }
    if (!Number.isSafeInteger(raw.responseStatus) || raw.responseStatus < 100 || raw.responseStatus > 599) {
      throw new PageCaptureError("invalid_page_capture_status", "responseStatus must be an HTTP status from 100 through 599");
    }
    const viewport = normalizePageCaptureViewport(raw.viewport);
    const screenshotHash = sha256Digest(raw.screenshot.sha256, "screenshot.sha256");
    const fullPageScreenshotHash = raw.fullPageScreenshot
      ? sha256Digest(raw.fullPageScreenshot.sha256, "fullPageScreenshot.sha256")
      : undefined;
    if (viewport.fullPage && !raw.fullPageScreenshot) {
      throw new PageCaptureError("full_page_artifact_required", "A full-page viewport declaration requires a full-page screenshot artifact");
    }
    if (!viewport.fullPage && raw.fullPageScreenshot) {
      throw new PageCaptureError("unexpected_full_page_artifact", "A full-page screenshot cannot be linked when viewport.fullPage is false");
    }
    if (raw.fullPageScreenshot?.artifactId === raw.screenshot.artifactId) {
      throw new PageCaptureError("duplicate_page_capture_artifact", "Viewport and full-page screenshots must use distinct artifact records");
    }
    const capturedAt = pageCaptureTimestamp(raw.capturedAt, "capturedAt");
    if (Date.parse(capturedAt) > this.clock().getTime() + 5 * 60_000) {
      throw new PageCaptureError("future_page_capture", "capturedAt cannot be more than five minutes in the future");
    }
    if (actor.type === "agent" && actor.id !== capturedByAgentId) {
      throw new PageCaptureError("page_capture_actor_mismatch", "An agent cannot attribute a page capture to another agent");
    }
    const captureAgent = this.database.prepare("SELECT id FROM agents WHERE id = ?")
      .get(capturedByAgentId) as AgentRow | undefined;
    if (!captureAgent) {
      throw new PageCaptureError("capture_agent_not_found", "Capture agent was not found");
    }

    const sensitivity = raw.sensitivity;
    this.assertArtifact(
      missionId, runId, stepId, raw.screenshot.artifactId, screenshotHash, sensitivity, "screenshot",
    );
    if (raw.fullPageScreenshot && fullPageScreenshotHash) {
      this.assertArtifact(
        missionId, runId, stepId, raw.fullPageScreenshot.artifactId,
        fullPageScreenshotHash, sensitivity, "full-page screenshot",
      );
    }
    const related: PageCaptureRelatedRecords = {
      evidenceIds: uniqueIds(raw.evidenceIds, "evidenceIds"),
      observationIds: uniqueIds(raw.observationIds, "observationIds"),
      findingIds: uniqueIds(raw.findingIds, "findingIds"),
    };
    for (const evidenceId of related.evidenceIds) {
      this.assertLinkedRecord("evidence", evidenceId, missionId, runId, stepId, sensitivity);
    }
    for (const observationId of related.observationIds) {
      const observation = this.assertLinkedRecord("observations", observationId, missionId, runId, stepId, sensitivity);
      if (assetNodeId && observation.asset_id && observation.asset_id !== assetNodeId) {
        throw new PageCaptureError("page_capture_link_scope_mismatch", "Observation belongs to a different asset");
      }
    }
    for (const findingId of related.findingIds) {
      this.assertLinkedRecord("findings", findingId, missionId, runId, undefined, sensitivity);
      const linked = this.database.prepare(`
        SELECT 1 FROM finding_evidence
        WHERE finding_id = ? AND evidence_id IN (${related.evidenceIds.map(() => "?").join(",") || "NULL"})
        LIMIT 1
      `).get(findingId, ...related.evidenceIds);
      if (!linked) {
        throw new PageCaptureError(
          "page_capture_finding_evidence_required",
          "Every linked finding must already be connected to at least one supplied evidence record",
        );
      }
    }

    return {
      missionId,
      runId,
      ...(stepId ? { stepId } : {}),
      ...(assetNodeId ? { assetNodeId } : {}),
      ...(serviceNodeId ? { serviceNodeId } : {}),
      normalizedUrl,
      responseStatus: raw.responseStatus,
      ...(title ? { title } : {}),
      viewport,
      screenshotArtifactId: stablePageCaptureIdentifier(raw.screenshot.artifactId, "screenshot.artifactId"),
      ...(raw.fullPageScreenshot
        ? { fullPageArtifactId: stablePageCaptureIdentifier(raw.fullPageScreenshot.artifactId, "fullPageScreenshot.artifactId") }
        : {}),
      contentHash: sha256Digest(raw.contentHash, "contentHash"),
      certificate,
      site,
      related,
      screenshotHash,
      ...(fullPageScreenshotHash ? { fullPageScreenshotHash } : {}),
      capturedByAgentId,
      captureTool,
      sensitivity,
      redactionState: raw.redactionState,
      capturedAt,
    };
  }

  private assertMission(missionId: string): MissionRow {
    const row = this.database.prepare("SELECT authorization_status FROM missions WHERE id = ?")
      .get(missionId) as MissionRow | undefined;
    if (!row) throw new PageCaptureError("mission_not_found", `Mission not found: ${missionId}`);
    return row;
  }

  private assertRun(missionId: string, runId: string): void {
    const row = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(runId) as RunRow | undefined;
    if (!row) throw new PageCaptureError("run_not_found", `Run not found: ${runId}`);
    if (row.mission_id !== missionId) throw new PageCaptureError("page_capture_run_scope_mismatch", "Run does not belong to the capture mission");
  }

  private assertStep(runId: string, planId: string | undefined, stepId: string): void {
    const row = this.database.prepare("SELECT run_id, plan_id FROM plan_steps WHERE id = ?").get(stepId) as StepRow | undefined;
    if (!row) throw new PageCaptureError("plan_step_not_found", "Page-capture plan step was not found");
    if (row.run_id !== runId || (planId && row.plan_id !== planId)) {
      throw new PageCaptureError("page_capture_step_scope_mismatch", "Plan step does not belong to the supplied run and plan");
    }
  }

  private assertNode(
    missionId: string,
    runId: string | undefined,
    nodeId: string,
    kind: "asset" | "service",
  ): TopologyRow {
    const row = this.database.prepare(`
      SELECT mission_id, run_id, node_type, scope_status FROM topology_nodes WHERE id = ?
    `).get(nodeId) as TopologyRow | undefined;
    if (!row) throw new PageCaptureError(`${kind}_node_not_found`, `${kind} topology node was not found`);
    if (row.mission_id !== missionId || (runId && row.run_id && row.run_id !== runId)) {
      throw new PageCaptureError("page_capture_topology_scope_mismatch", `${kind} topology node is outside the mission/run`);
    }
    const allowedTypes = kind === "asset" ? ASSET_NODE_TYPES : SERVICE_NODE_TYPES;
    if (!allowedTypes.has(row.node_type)) {
      throw new PageCaptureError("page_capture_node_type_mismatch", `${kind} reference points to a ${row.node_type} topology node`);
    }
    if (row.scope_status !== "allowed") {
      throw new PageCaptureError("page_capture_target_out_of_scope", `${kind} topology node is not in allowed scope`);
    }
    return row;
  }

  private assertUrlAuthorized(missionId: string, normalizedUrl: string): void {
    const targets = this.database.prepare(`
      SELECT target_type, disposition, normalized_target
      FROM mission_targets WHERE mission_id = ?
    `).all(missionId) as TargetRow[];
    const url = new URL(normalizedUrl);
    if (targets.some((target) => target.disposition === "prohibited" && targetMatches(target, url))) {
      throw new PageCaptureError("page_capture_target_prohibited", "Capture URL matches a prohibited mission target");
    }
    if (!targets.some((target) => target.disposition === "allowed" && targetMatches(target, url))) {
      throw new PageCaptureError("page_capture_target_out_of_scope", "Capture URL is outside the normalized authorized target set");
    }
  }

  private assertArtifact(
    missionId: string,
    runId: string,
    stepId: string | undefined,
    artifactIdValue: string,
    expectedHash: string,
    sensitivity: Sensitivity,
    label: string,
  ): void {
    const artifactId = stablePageCaptureIdentifier(artifactIdValue, `${label} artifactId`);
    const row = this.database.prepare(`
      SELECT mission_id, run_id, step_id, artifact_type, content_hash,
             byte_size, media_type, sensitivity
      FROM artifacts WHERE id = ?
    `).get(artifactId) as ArtifactRow | undefined;
    if (!row) throw new PageCaptureError("page_capture_artifact_not_found", `${label} artifact was not found`);
    if (row.mission_id !== missionId || row.run_id !== runId || (row.step_id ?? undefined) !== stepId) {
      throw new PageCaptureError("page_capture_artifact_scope_mismatch", `${label} artifact is outside the capture mission/run/step`);
    }
    if (!SCREENSHOT_ARTIFACT_TYPES.has(row.artifact_type) || !row.media_type || !SCREENSHOT_MEDIA_TYPES.has(row.media_type)) {
      throw new PageCaptureError("invalid_page_capture_artifact", `${label} artifact is not a supported immutable screenshot image`);
    }
    if (row.byte_size <= 0 || row.content_hash !== expectedHash) {
      throw new PageCaptureError("page_capture_artifact_hash_mismatch", `${label} artifact hash or byte size does not match the supplied result`);
    }
    if (!sensitivityCovers(sensitivity, row.sensitivity)) {
      throw new PageCaptureError("page_capture_sensitivity_downgrade", `${label} artifact sensitivity cannot be downgraded`);
    }
  }

  private assertLinkedRecord(
    table: "evidence" | "observations" | "findings",
    id: string,
    missionId: string,
    runId: string,
    stepId: string | undefined,
    sensitivity: Sensitivity,
  ): LinkedRecordRow {
    const columns = table === "observations"
      ? "mission_id, run_id, step_id, asset_id, sensitivity"
      : table === "evidence"
        ? "mission_id, run_id, step_id, sensitivity"
        : "mission_id, run_id";
    const row = this.database.prepare(`SELECT ${columns} FROM ${table} WHERE id = ?`)
      .get(id) as LinkedRecordRow | undefined;
    if (!row) throw new PageCaptureError(`page_capture_${table}_not_found`, `Linked ${table} record was not found`);
    if (row.mission_id !== missionId || (row.run_id !== null && row.run_id !== runId)) {
      throw new PageCaptureError("page_capture_link_scope_mismatch", `Linked ${table} record is outside the capture mission/run`);
    }
    if (stepId && row.step_id && row.step_id !== stepId) {
      throw new PageCaptureError("page_capture_link_scope_mismatch", `Linked ${table} record belongs to another plan step`);
    }
    if (row.sensitivity && !sensitivityCovers(sensitivity, row.sensitivity)) {
      throw new PageCaptureError("page_capture_sensitivity_downgrade", `Linked ${table} record sensitivity cannot be downgraded`);
    }
    return row;
  }
}
