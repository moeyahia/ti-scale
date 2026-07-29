import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import type { SqliteDatabase } from "../db";
import { canonicalJson } from "../run-intelligence/serialization";
import type {
  PageCaptureCertificateMetadata,
  PageCaptureListFilter,
  PageCaptureRecord,
  PageCaptureRedactionState,
  PageCaptureRelatedRecords,
  PageCaptureSiteMetadata,
  PageCaptureViewport,
} from "./types";
import { PageCaptureError } from "./types";
import {
  parsePageCaptureCertificateMetadata,
  parsePageCaptureSiteMetadata,
  parsePageCaptureViewport,
  sha256Digest,
  stablePageCaptureIdentifier,
} from "./validation";

type PreparedStatement = Database.Statement<unknown[], unknown>;

interface PageCaptureRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly asset_node_id: string | null;
  readonly service_node_id: string | null;
  readonly normalized_url: string;
  readonly response_status: number | null;
  readonly title: string | null;
  readonly viewport_json: string;
  readonly screenshot_artifact_id: string | null;
  readonly full_page_artifact_id: string | null;
  readonly content_hash: string;
  readonly certificate_metadata_json: string;
  readonly captured_by_agent_id: string | null;
  readonly capture_tool: string;
  readonly sensitivity: PageCaptureRecord["sensitivity"];
  readonly redaction_state: PageCaptureRedactionState;
  readonly captured_at: string;
  readonly created_at: string;
  readonly plan_id: string | null;
  readonly step_title: string | null;
  readonly asset_label: string | null;
  readonly service_label: string | null;
  readonly captured_by_agent_name: string | null;
  readonly screenshot_content_hash: string | null;
  readonly screenshot_media_type: string | null;
  readonly screenshot_byte_size: number | null;
  readonly full_page_content_hash: string | null;
  readonly full_page_media_type: string | null;
  readonly full_page_byte_size: number | null;
}

interface StoredCaptureMetadata {
  readonly schemaVersion: 1;
  readonly certificate: PageCaptureCertificateMetadata;
  readonly site: PageCaptureSiteMetadata;
  readonly related: PageCaptureRelatedRecords;
  readonly hashes: {
    readonly screenshotSha256: string;
    readonly fullPageSha256?: string;
  };
}

export interface PersistPageCaptureInput {
  readonly missionId: string;
  readonly runId: string;
  readonly stepId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly normalizedUrl: string;
  readonly responseStatus: number;
  readonly title?: string;
  readonly viewport: PageCaptureViewport;
  readonly screenshotArtifactId: string;
  readonly fullPageArtifactId?: string;
  readonly contentHash: string;
  readonly certificate: PageCaptureCertificateMetadata;
  readonly site: PageCaptureSiteMetadata;
  readonly related: PageCaptureRelatedRecords;
  readonly screenshotHash: string;
  readonly fullPageScreenshotHash?: string;
  readonly capturedByAgentId: string;
  readonly captureTool: string;
  readonly sensitivity: PageCaptureRecord["sensitivity"];
  readonly redactionState: PageCaptureRedactionState;
  readonly capturedAt: string;
}

function plainRecord(value: unknown): Readonly<Record<string, unknown>> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new PageCaptureError("page_capture_data_corrupt", "Stored page capture metadata is malformed");
  }
  return value as Readonly<Record<string, unknown>>;
}

function stringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new PageCaptureError("page_capture_data_corrupt", `Stored page capture ${label} links are malformed`);
  }
  const result = value.map((item) => stablePageCaptureIdentifier(item, `stored ${label} ID`));
  if (new Set(result).size !== result.length) {
    throw new PageCaptureError("page_capture_data_corrupt", `Stored page capture ${label} links contain duplicates`);
  }
  return result;
}

function storedMetadata(serialized: string): StoredCaptureMetadata {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized) as unknown; } catch {
    throw new PageCaptureError("page_capture_data_corrupt", "Stored page capture metadata is not valid JSON");
  }
  const record = plainRecord(parsed);
  if (record.schemaVersion !== 1) {
    throw new PageCaptureError("page_capture_data_corrupt", "Stored page capture metadata schema is unsupported");
  }
  const related = plainRecord(record.related);
  const hashes = plainRecord(record.hashes);
  if (typeof hashes.screenshotSha256 !== "string") {
    throw new PageCaptureError("page_capture_data_corrupt", "Stored page capture screenshot hash is missing");
  }
  return {
    schemaVersion: 1,
    certificate: parsePageCaptureCertificateMetadata(record.certificate),
    site: parsePageCaptureSiteMetadata(record.site),
    related: {
      evidenceIds: stringArray(related.evidenceIds, "evidence"),
      observationIds: stringArray(related.observationIds, "observation"),
      findingIds: stringArray(related.findingIds, "finding"),
    },
    hashes: {
      screenshotSha256: sha256Digest(hashes.screenshotSha256, "stored screenshot hash"),
      ...(typeof hashes.fullPageSha256 === "string"
        ? { fullPageSha256: sha256Digest(hashes.fullPageSha256, "stored full-page screenshot hash") }
        : {}),
    },
  };
}

function artifactProjection(
  id: string | null,
  hash: string | null,
  mediaType: string | null,
  byteSize: number | null,
): PageCaptureRecord["screenshot"] {
  if (!id || !hash || !mediaType || byteSize === null) return undefined;
  return { artifactId: id, contentHash: hash, mediaType, byteSize };
}

function storedViewport(serialized: string): PageCaptureViewport {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized) as unknown; } catch {
    throw new PageCaptureError("page_capture_data_corrupt", "Stored page capture viewport is not valid JSON");
  }
  return parsePageCaptureViewport(parsed);
}

function mapRecord(row: PageCaptureRow): PageCaptureRecord {
  const metadata = storedMetadata(row.certificate_metadata_json);
  const screenshot = artifactProjection(
    row.screenshot_artifact_id,
    row.screenshot_content_hash,
    row.screenshot_media_type,
    row.screenshot_byte_size,
  );
  const fullPageScreenshot = artifactProjection(
    row.full_page_artifact_id,
    row.full_page_content_hash,
    row.full_page_media_type,
    row.full_page_byte_size,
  );
  const visible = row.redaction_state === "not_required" || row.redaction_state === "redacted";
  let galleryEndpoint = row.normalized_url;
  try {
    const url = new URL(row.normalized_url);
    url.search = "";
    galleryEndpoint = url.toString();
  } catch { /* The canonical record remains readable; the service validates new URLs. */ }
  return {
    id: row.id,
    missionId: row.mission_id,
    ...(row.run_id ? { runId: row.run_id } : {}),
    ...(row.plan_id ? { planId: row.plan_id } : {}),
    ...(row.step_id ? { stepId: row.step_id } : {}),
    ...(row.step_title ? { stepTitle: row.step_title } : {}),
    ...(row.asset_node_id ? { assetNodeId: row.asset_node_id } : {}),
    ...(row.asset_label ? { assetLabel: row.asset_label } : {}),
    ...(row.service_node_id ? { serviceNodeId: row.service_node_id } : {}),
    ...(row.service_label ? { serviceLabel: row.service_label } : {}),
    normalizedUrl: row.normalized_url,
    ...(row.response_status === null ? {} : { responseStatus: row.response_status }),
    ...(row.title ? { title: row.title } : {}),
    viewport: storedViewport(row.viewport_json),
    ...(screenshot ? { screenshot } : {}),
    ...(fullPageScreenshot ? { fullPageScreenshot } : {}),
    contentHash: row.content_hash,
    screenshotHash: metadata.hashes.screenshotSha256,
    ...(metadata.hashes.fullPageSha256 ? { fullPageScreenshotHash: metadata.hashes.fullPageSha256 } : {}),
    certificate: metadata.certificate,
    site: metadata.site,
    related: metadata.related,
    ...(row.captured_by_agent_id ? { capturedByAgentId: row.captured_by_agent_id } : {}),
    ...(row.captured_by_agent_name ? { capturedByAgentName: row.captured_by_agent_name } : {}),
    captureTool: row.capture_tool,
    sensitivity: row.sensitivity,
    redactionState: row.redaction_state,
    capturedAt: row.captured_at,
    createdAt: row.created_at,
    gallery: {
      label: row.title ?? galleryEndpoint,
      previewArtifactId: visible && screenshot ? screenshot.artifactId : null,
      fullPageArtifactId: visible && fullPageScreenshot ? fullPageScreenshot.artifactId : null,
      previewAvailable: visible && Boolean(screenshot),
      redactionState: row.redaction_state,
    },
  };
}

const SELECT_PROJECTION = `
  SELECT pc.*,
    ps.plan_id AS plan_id,
    ps.title AS step_title,
    asset.primary_label AS asset_label,
    service.primary_label AS service_label,
    agent.display_name AS captured_by_agent_name,
    screenshot.content_hash AS screenshot_content_hash,
    screenshot.media_type AS screenshot_media_type,
    screenshot.byte_size AS screenshot_byte_size,
    full_page.content_hash AS full_page_content_hash,
    full_page.media_type AS full_page_media_type,
    full_page.byte_size AS full_page_byte_size
  FROM page_captures pc
  LEFT JOIN plan_steps ps ON ps.id = pc.step_id
  LEFT JOIN topology_nodes asset ON asset.id = pc.asset_node_id
  LEFT JOIN topology_nodes service ON service.id = pc.service_node_id
  LEFT JOIN agents agent ON agent.id = pc.captured_by_agent_id
  LEFT JOIN artifacts screenshot ON screenshot.id = pc.screenshot_artifact_id
  LEFT JOIN artifacts full_page ON full_page.id = pc.full_page_artifact_id
`;

/** Prepared, immutable page-capture persistence over migration 010. */
export class PageCaptureRepository {
  private readonly findById: PreparedStatement;
  private readonly findCanonicalStatement: PreparedStatement;
  private readonly listStatement: PreparedStatement;
  private readonly insertStatement: PreparedStatement;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly idFactory: () => string = () => `capture_${randomUUID()}`,
  ) {
    this.findById = database.prepare(`${SELECT_PROJECTION} WHERE pc.id = ?`);
    this.findCanonicalStatement = database.prepare(`
      ${SELECT_PROJECTION}
      WHERE pc.mission_id = ? AND pc.normalized_url = ? AND pc.content_hash = ?
      LIMIT 1
    `);
    this.listStatement = database.prepare(`
      ${SELECT_PROJECTION}
      WHERE pc.mission_id = @missionId
        AND (@runId IS NULL OR pc.run_id = @runId)
        AND (@assetNodeId IS NULL OR pc.asset_node_id = @assetNodeId)
        AND (@serviceNodeId IS NULL OR pc.service_node_id = @serviceNodeId)
        AND (@redactionState IS NULL OR pc.redaction_state = @redactionState)
        AND (
          @cursorAt IS NULL
          OR pc.captured_at < @cursorAt
          OR (pc.captured_at = @cursorAt AND pc.id < @cursorId)
        )
      ORDER BY pc.captured_at DESC, pc.id DESC
      LIMIT @limit
    `);
    this.insertStatement = database.prepare(`
      INSERT INTO page_captures (
        id, mission_id, run_id, step_id, asset_node_id, service_node_id,
        normalized_url, response_status, title, viewport_json,
        screenshot_artifact_id, full_page_artifact_id, content_hash,
        certificate_metadata_json, captured_by_agent_id, capture_tool,
        sensitivity, redaction_state, captured_at, created_at
      ) VALUES (
        @id, @missionId, @runId, @stepId, @assetNodeId, @serviceNodeId,
        @normalizedUrl, @responseStatus, @title, @viewportJson,
        @screenshotArtifactId, @fullPageArtifactId, @contentHash,
        @metadataJson, @capturedByAgentId, @captureTool,
        @sensitivity, @redactionState, @capturedAt, @createdAt
      )
    `);
  }

  get(id: string): PageCaptureRecord {
    const row = this.findById.get(id) as PageCaptureRow | undefined;
    if (!row) throw new PageCaptureError("page_capture_not_found", `Page capture not found: ${id}`);
    return mapRecord(row);
  }

  findCanonical(missionId: string, normalizedUrl: string, contentHash: string): PageCaptureRecord | undefined {
    const row = this.findCanonicalStatement.get(missionId, normalizedUrl, contentHash) as PageCaptureRow | undefined;
    return row ? mapRecord(row) : undefined;
  }

  list(filter: PageCaptureListFilter): readonly PageCaptureRecord[] {
    const rows = this.listStatement.all({
      missionId: filter.missionId,
      runId: filter.runId ?? null,
      assetNodeId: filter.assetNodeId ?? null,
      serviceNodeId: filter.serviceNodeId ?? null,
      redactionState: filter.redactionState ?? null,
      cursorAt: filter.cursor?.capturedAt ?? null,
      cursorId: filter.cursor?.id ?? null,
      limit: filter.limit ?? 51,
    }) as PageCaptureRow[];
    return rows.map(mapRecord);
  }

  insert(input: PersistPageCaptureInput, createdAt: string): PageCaptureRecord {
    const id = this.idFactory();
    const metadata: StoredCaptureMetadata = {
      schemaVersion: 1,
      certificate: input.certificate,
      site: input.site,
      related: input.related,
      hashes: {
        screenshotSha256: input.screenshotHash,
        ...(input.fullPageScreenshotHash ? { fullPageSha256: input.fullPageScreenshotHash } : {}),
      },
    };
    this.insertStatement.run({
      id,
      missionId: input.missionId,
      runId: input.runId,
      stepId: input.stepId ?? null,
      assetNodeId: input.assetNodeId ?? null,
      serviceNodeId: input.serviceNodeId ?? null,
      normalizedUrl: input.normalizedUrl,
      responseStatus: input.responseStatus,
      title: input.title ?? null,
      viewportJson: canonicalJson(input.viewport),
      screenshotArtifactId: input.screenshotArtifactId,
      fullPageArtifactId: input.fullPageArtifactId ?? null,
      contentHash: input.contentHash,
      metadataJson: canonicalJson(metadata),
      capturedByAgentId: input.capturedByAgentId,
      captureTool: input.captureTool,
      sensitivity: input.sensitivity,
      redactionState: input.redactionState,
      capturedAt: input.capturedAt,
      createdAt,
    });
    return this.get(id);
  }
}
