import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type { VaultPathPolicy } from "../vault";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { OperationsApiError, conflict, forbidden, notFound } from "./errors";
import { missionScopeSql, sensitivitySql } from "./scope";
import type {
  OperationsAccessPolicy,
  OperationsActor,
  OperationsSensitivity,
} from "./types";
import { OPERATIONS_SCHEMA_VERSION } from "./types";
import {
  canonicalJson,
  parseJson,
  sanitizeJson,
  sha256,
} from "./validation";

type Row = Record<string, unknown>;

const DEFAULT_MAXIMUM_ARTIFACT_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAXIMUM_EXPORT_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAXIMUM_EXPORT_RECORDS = 1_000;
const MAXIMUM_STRING_LENGTH = 4_096;
const LOCATION_URI = /\b[a-z][a-z0-9+.-]*:\/\/[^\s,;)'"<>]+/giu;
const POSIX_LOCATION = /(^|[\s'"(])\/(?:[^/\s'"()]+\/)*[^/\s'"()]+/gu;
const WINDOWS_LOCATION = /\b[A-Za-z]:\\(?:[^\\\s'"()]+\\)*[^\\\s'"()]+/gu;

interface RunScopeRow {
  readonly id: string;
  readonly mission_id: string;
  readonly mission_name: string;
  readonly engagement_id: string | null;
  readonly journey: "autonomous" | "guided";
  readonly status: string;
}

interface ArtifactStorageReference {
  readonly connectionId: string;
  readonly contentHash: string;
}

interface DownloadArtifactRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly journey: "autonomous" | "guided";
  readonly mission_control_plane: "legacy" | "ti_scale";
  readonly linked_run_id: string | null;
  readonly run_control_plane: "legacy" | "ti_scale" | null;
  readonly artifact_type: string;
  readonly storage_uri: string;
  readonly content_hash: string;
  readonly byte_size: number;
  readonly metadata_json: string;
}

interface VaultConnectionRow {
  readonly id: string;
  readonly vault_path: string;
  readonly status: "disconnected" | "connecting" | "connected" | "degraded" | "error";
  readonly permission_granted_at: string;
}

export interface SecureArtifactDownload {
  readonly artifactId: string;
  readonly missionId: string;
  readonly runId: string | null;
  readonly body: Buffer;
  readonly byteSize: number;
  readonly contentHash: string;
  readonly filename: string;
  /** Content is deliberately served as an inert attachment, never inline. */
  readonly mediaType: "application/octet-stream";
}

export type SecureArtifactDeliveryState =
  | "ready"
  | "metadata_only"
  | "reconciliation_required"
  | "quarantined";

/**
 * Actor-specific content-delivery eligibility. This projection never contains
 * a storage URI or filesystem path; the download endpoint re-evaluates the
 * same boundary immediately before opening a content-addressed file.
 */
export interface SecureArtifactDeliveryDescriptor {
  readonly state: SecureArtifactDeliveryState;
  readonly downloadable: boolean;
  readonly code: string;
  readonly reason: string;
  readonly remediation: string | null;
  readonly verifiedEvidenceCount: number;
}

export interface SecureExportServiceOptions {
  readonly vaultPathPolicy?: VaultPathPolicy;
  readonly maximumArtifactBytes?: number;
  readonly maximumExportBytes?: number;
  readonly maximumExportRecords?: number;
  readonly clock?: () => Date;
}

function configuredBound(value: number | undefined, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`Secure export bound must be an integer between 1 and ${maximum}`);
  }
  return value;
}

function parseVaultAttachmentStorageUri(value: string): ArtifactStorageReference {
  const match = /^vault-attachment:\/\/([^/?#]+)\/([a-f0-9]{64})$/u.exec(value);
  if (!match) {
    throw conflict(
      "This artifact storage scheme is not available through the canonical content-delivery boundary.",
      "Use a content-addressed Obsidian attachment or export the artifact metadata instead.",
    );
  }
  let connectionId: string;
  try {
    connectionId = decodeURIComponent(match[1]!);
  } catch {
    throw conflict("The canonical artifact storage reference is malformed.");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(connectionId)) {
    throw conflict("The canonical artifact storage reference is malformed.");
  }
  return { connectionId, contentHash: match[2]! };
}

function boundedSanitized(value: unknown, depth = 0): unknown {
  const sanitized = depth === 0 ? sanitizeJson(value) : value;
  if (depth > 8) return "[REDACTED: depth limit]";
  if (typeof sanitized === "string") {
    const redacted = sanitized
      .replace(LOCATION_URI, "[REDACTED LOCATION]")
      .replace(POSIX_LOCATION, "$1[REDACTED LOCATION]")
      .replace(WINDOWS_LOCATION, "[REDACTED LOCATION]");
    return redacted.length <= MAXIMUM_STRING_LENGTH
      ? redacted
      : `${redacted.slice(0, MAXIMUM_STRING_LENGTH)}[TRUNCATED]`;
  }
  if (Array.isArray(sanitized)) {
    return sanitized.slice(0, 100).map((item) => boundedSanitized(item, depth + 1));
  }
  if (sanitized && typeof sanitized === "object") {
    return Object.fromEntries(
      Object.entries(sanitized as Record<string, unknown>)
        .slice(0, 100)
        .map(([key, item]) => [key, boundedSanitized(item, depth + 1)]),
    );
  }
  return sanitized;
}

function safeDownloadId(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/gu, "_").slice(0, 96) || "export";
}

function storageScheme(value: string): string {
  return /^([a-z][a-z0-9+.-]*):/iu.exec(value)?.[1]?.toLocaleLowerCase("en-US") ?? "unknown";
}

function artifactIsQuarantined(artifact: DownloadArtifactRow): boolean {
  const scheme = storageScheme(artifact.storage_uri);
  if (scheme === "quarantine" || scheme === "quarantined") return true;
  const metadata = parseJson(artifact.metadata_json);
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return false;
  const record = metadata as Record<string, unknown>;
  return record.quarantined === true
    || record.lifecycleState === "quarantined"
    || record.storageState === "quarantined";
}

function deliveryDescriptor(input: Omit<SecureArtifactDeliveryDescriptor, "downloadable"> & {
  readonly downloadable?: boolean;
}): SecureArtifactDeliveryDescriptor {
  return { ...input, downloadable: input.downloadable ?? false };
}

/**
 * Narrow delivery boundary for canonical V2 exports and the one artifact
 * storage scheme with a configured, content-addressed filesystem root.
 */
export class SecureExportService {
  readonly #database: SqliteDatabase;
  readonly #vaultPathPolicy?: VaultPathPolicy;
  readonly #maximumArtifactBytes: number;
  readonly #maximumExportBytes: number;
  readonly #maximumExportRecords: number;
  readonly #clock: () => Date;

  constructor(database: SqliteDatabase, options: SecureExportServiceOptions = {}) {
    this.#database = database;
    this.#vaultPathPolicy = options.vaultPathPolicy;
    this.#maximumArtifactBytes = configuredBound(
      options.maximumArtifactBytes,
      DEFAULT_MAXIMUM_ARTIFACT_BYTES,
      256 * 1024 * 1024,
    );
    this.#maximumExportBytes = configuredBound(
      options.maximumExportBytes,
      DEFAULT_MAXIMUM_EXPORT_BYTES,
      64 * 1024 * 1024,
    );
    this.#maximumExportRecords = configuredBound(
      options.maximumExportRecords,
      DEFAULT_MAXIMUM_EXPORT_RECORDS,
      10_000,
    );
    this.#clock = options.clock ?? (() => new Date());
  }

  describeArtifactDelivery(
    artifactId: string,
    access: OperationsAccessPolicy,
  ): SecureArtifactDeliveryDescriptor {
    const artifact = this.#artifact(artifactId, access);
    return this.#describeArtifact(artifact, access);
  }

  downloadArtifact(
    artifactId: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
  ): SecureArtifactDownload {
    if (!access.canDownloadArtifactContent) {
      throw forbidden("This identity cannot download artifact content.");
    }
    const artifact = this.#artifact(artifactId, access);
    const descriptor = this.#describeArtifact(artifact, access);
    if (!descriptor.downloadable) this.#throwDeliveryFailure(descriptor);

    const expectedHash = String(artifact.content_hash).toLowerCase();
    const expectedSize = Number(artifact.byte_size);
    if (
      !/^[a-f0-9]{64}$/u.test(expectedHash)
      || !Number.isSafeInteger(expectedSize)
      || expectedSize < 0
      || expectedSize > this.#maximumArtifactBytes
    ) {
      throw conflict("Canonical artifact integrity metadata is invalid or exceeds the download limit.");
    }
    const storage = parseVaultAttachmentStorageUri(String(artifact.storage_uri));
    if (storage.contentHash !== expectedHash) {
      throw conflict("The artifact storage reference does not match its canonical SHA-256 record.");
    }
    const connection = this.#database.prepare(`
      SELECT id, vault_path, status, permission_granted_at
      FROM vault_connections WHERE id = ?
    `).get(storage.connectionId) as VaultConnectionRow | undefined;
    if (
      !connection
      || !connection.permission_granted_at
      || !["connected", "degraded"].includes(connection.status)
    ) {
      throw conflict("The canonical vault connection is not available for artifact delivery.");
    }

    let fileDescriptor: number | undefined;
    let body: Buffer;
    try {
      const vaultRoot = this.#vaultPathPolicy!.resolveExistingVault(connection.vault_path);
      const path = this.#vaultPathPolicy!.resolveRelative(
        vaultRoot,
        `.ti-scale/attachments/${expectedHash}`,
      );
      fileDescriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const before = fstatSync(fileDescriptor);
      if (!before.isFile() || before.size !== expectedSize || before.size > this.#maximumArtifactBytes) {
        throw new Error("artifact_size_or_type_mismatch");
      }
      body = readFileSync(fileDescriptor);
      const after = fstatSync(fileDescriptor);
      if (!after.isFile() || after.size !== before.size || body.length !== expectedSize) {
        throw new Error("artifact_changed_during_verification");
      }
      const actualHash = createHash("sha256").update(body).digest("hex");
      if (actualHash !== expectedHash) throw new Error("artifact_hash_mismatch");
    } catch {
      throw new OperationsApiError(
        409,
        "artifact_integrity_reconciliation_required",
        "The canonical artifact failed containment or integrity verification.",
        {
          humanMessage: "The artifact could not be delivered because its contained file, byte size, or SHA-256 no longer matches the canonical record.",
          category: "reconciliation_required",
          remediation: "Restore the content-addressed regular file from a trusted backup and verify the vault before retrying.",
        },
      );
    } finally {
      if (fileDescriptor !== undefined) closeSync(fileDescriptor);
    }

    const now = this.#clock().toISOString();
    this.#appendAudit({
      missionId: artifact.mission_id,
      runId: artifact.run_id,
      journey: artifact.journey,
      actor,
      action: "artifact.content_downloaded",
      resourceType: "artifact",
      resourceId: artifact.id,
      reason: "Authorized operator downloaded verified canonical artifact content.",
      details: {
        storageScheme: "vault-attachment",
        contentHash: expectedHash,
        byteSize: expectedSize,
        inertAttachment: true,
      },
      occurredAt: now,
    });
    return {
      artifactId: artifact.id,
      missionId: artifact.mission_id,
      runId: artifact.run_id,
      body,
      byteSize: expectedSize,
      contentHash: expectedHash,
      filename: `ti-scale-artifact-${safeDownloadId(artifact.id)}.bin`,
      mediaType: "application/octet-stream",
    };
  }

  #artifact(artifactId: string, access: OperationsAccessPolicy): DownloadArtifactRow {
    const scope = missionScopeSql("m", access);
    const sensitivity = sensitivitySql("a.sensitivity", access);
    const artifact = this.#database.prepare(`
      SELECT a.*, m.control_plane AS mission_control_plane,
        linked_run.id AS linked_run_id,
        linked_run.control_plane AS run_control_plane
      FROM artifacts a
      JOIN missions m ON m.id = a.mission_id
      LEFT JOIN runs linked_run
        ON linked_run.id = a.run_id AND linked_run.mission_id = a.mission_id
      WHERE a.id = ? AND ${scope.sql} AND ${sensitivity.sql}
    `).get(artifactId, ...scope.params, ...sensitivity.params) as DownloadArtifactRow | undefined;
    if (!artifact) {
      throw new OperationsApiError(404, "artifact_content_not_found", "Artifact content was not found", {
        humanMessage: "The requested artifact does not exist or is outside your authorized scope.",
        category: "not_found",
        remediation: "Open a canonical artifact link returned by the authorized Intelligence API.",
      });
    }
    return artifact;
  }

  #verifiedEvidenceCount(
    artifact: DownloadArtifactRow,
    access: OperationsAccessPolicy,
  ): number {
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const row = this.#database.prepare(`
      SELECT COUNT(*) AS count
      FROM evidence e
      LEFT JOIN runs evidence_run
        ON evidence_run.id = e.run_id AND evidence_run.mission_id = e.mission_id
      WHERE e.artifact_id = ?
        AND e.mission_id = ?
        AND e.run_id IS ?
        AND ${verifiedEvidenceSql("e")}
        AND ${sensitivity.sql}
        AND (e.run_id IS NULL OR evidence_run.id IS NOT NULL)
    `).get(
      artifact.id,
      artifact.mission_id,
      artifact.run_id,
      ...sensitivity.params,
    ) as { count: number };
    return Number(row.count);
  }

  #describeArtifact(
    artifact: DownloadArtifactRow,
    access: OperationsAccessPolicy,
  ): SecureArtifactDeliveryDescriptor {
    if (!access.canDownloadArtifactContent) {
      return deliveryDescriptor({
        state: "metadata_only",
        code: "artifact_download_permission_required",
        reason: "Your current role may inspect artifact metadata but cannot download artifact content.",
        remediation: "Ask an authorized reviewer or administrator to perform the bounded download.",
        verifiedEvidenceCount: 0,
      });
    }
    if (
      artifact.mission_control_plane !== "ti_scale"
      || (artifact.run_id !== null && (
        artifact.linked_run_id !== artifact.run_id
        || artifact.run_control_plane !== "ti_scale"
      ))
    ) {
      return deliveryDescriptor({
        state: "reconciliation_required",
        code: "artifact_control_plane_reconciliation_required",
        reason: "Artifact content is not owned by one canonical Ti-Scale mission and run boundary.",
        remediation: "Reconcile or explicitly transfer the imported mission/run before enabling V2 content delivery.",
        verifiedEvidenceCount: 0,
      });
    }
    if (artifactIsQuarantined(artifact)) {
      return deliveryDescriptor({
        state: "quarantined",
        code: "artifact_content_quarantined",
        reason: "This artifact is quarantined and cannot be delivered.",
        remediation: "Review the quarantine reason and create a new verified artifact; never bypass quarantine in place.",
        verifiedEvidenceCount: 0,
      });
    }
    if (
      artifact.artifact_type !== "obsidian_attachment"
      || storageScheme(artifact.storage_uri) !== "vault-attachment"
    ) {
      return deliveryDescriptor({
        state: "metadata_only",
        code: "artifact_delivery_adapter_unavailable",
        reason: "This artifact has no approved canonical content-delivery adapter.",
        remediation: "Use metadata inspection or create a content-addressed Obsidian attachment linked to verified evidence.",
        verifiedEvidenceCount: 0,
      });
    }

    const verifiedEvidenceCount = this.#verifiedEvidenceCount(artifact, access);
    if (verifiedEvidenceCount < 1) {
      return deliveryDescriptor({
        state: "reconciliation_required",
        code: "artifact_verified_evidence_required",
        reason: "No visible verified evidence canonically links this artifact to the same mission and run.",
        remediation: "Validate and link attributable evidence before making artifact content downloadable.",
        verifiedEvidenceCount,
      });
    }

    const expectedHash = String(artifact.content_hash).toLowerCase();
    const expectedSize = Number(artifact.byte_size);
    if (
      !/^[a-f0-9]{64}$/u.test(expectedHash)
      || !Number.isSafeInteger(expectedSize)
      || expectedSize < 0
      || expectedSize > this.#maximumArtifactBytes
    ) {
      return deliveryDescriptor({
        state: "reconciliation_required",
        code: "artifact_integrity_reconciliation_required",
        reason: "Canonical artifact integrity metadata is invalid or exceeds the download limit.",
        remediation: "Reconcile the immutable SHA-256 and byte-size record from a trusted source.",
        verifiedEvidenceCount,
      });
    }
    let storage: ArtifactStorageReference;
    try {
      storage = parseVaultAttachmentStorageUri(artifact.storage_uri);
    } catch {
      return deliveryDescriptor({
        state: "reconciliation_required",
        code: "artifact_integrity_reconciliation_required",
        reason: "The canonical artifact storage reference is malformed.",
        remediation: "Reconcile the content-addressed storage reference without exposing a filesystem path.",
        verifiedEvidenceCount,
      });
    }
    if (storage.contentHash !== expectedHash) {
      return deliveryDescriptor({
        state: "reconciliation_required",
        code: "artifact_integrity_reconciliation_required",
        reason: "The artifact storage reference does not match its canonical SHA-256 record.",
        remediation: "Restore the canonical content-addressed reference from a trusted source.",
        verifiedEvidenceCount,
      });
    }
    if (!this.#vaultPathPolicy) {
      return deliveryDescriptor({
        state: "reconciliation_required",
        code: "artifact_vault_reconciliation_required",
        reason: "Canonical artifact delivery is not configured for this deployment.",
        remediation: "Configure the same explicit vault root used by the Obsidian bridge before enabling content downloads.",
        verifiedEvidenceCount,
      });
    }
    const connection = this.#database.prepare(`
      SELECT id, vault_path, status, permission_granted_at
      FROM vault_connections WHERE id = ?
    `).get(storage.connectionId) as VaultConnectionRow | undefined;
    if (
      !connection
      || !connection.permission_granted_at
      || !["connected", "degraded"].includes(connection.status)
    ) {
      return deliveryDescriptor({
        state: "reconciliation_required",
        code: "artifact_vault_reconciliation_required",
        reason: "The canonical vault connection is not available for artifact delivery.",
        remediation: "Restore and verify the explicit vault connection before retrying.",
        verifiedEvidenceCount,
      });
    }
    return deliveryDescriptor({
      state: "ready",
      downloadable: true,
      code: "artifact_delivery_ready",
      reason: "Content is eligible for a bounded integrity-verified download.",
      remediation: null,
      verifiedEvidenceCount,
    });
  }

  #throwDeliveryFailure(descriptor: SecureArtifactDeliveryDescriptor): never {
    const status = descriptor.code === "artifact_download_permission_required" ? 403 : 409;
    throw new OperationsApiError(status, descriptor.code, descriptor.reason, {
      humanMessage: descriptor.reason,
      category: descriptor.state === "quarantined"
        ? "artifact_quarantined"
        : descriptor.code === "artifact_download_permission_required"
          ? "policy_denied"
          : "reconciliation_required",
      ...(descriptor.remediation ? { remediation: descriptor.remediation } : {}),
      details: {
        deliveryState: descriptor.state,
        verifiedEvidenceCount: descriptor.verifiedEvidenceCount,
      },
    });
  }

  exportEvidenceBundle(
    runId: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
  ): Record<string, unknown> {
    if (!access.canExportEvidenceBundles) {
      throw forbidden("This identity cannot export evidence bundles.");
    }
    const run = this.#requireRun(runId, access);
    const sensitivity = sensitivitySql("e.sensitivity", access);
    const evidenceRows = this.#database.prepare(`
      SELECT e.*
      FROM evidence e
      WHERE e.run_id = ? AND e.mission_id = ? AND ${sensitivity.sql}
        AND lower(trim(e.evidence_type)) <> 'command_output'
      ORDER BY e.acquired_at, e.id
      LIMIT ?
    `).all(runId, run.mission_id, ...sensitivity.params, this.#maximumExportRecords + 1) as Row[];
    const visibleEvidence = evidenceRows.slice(0, this.#maximumExportRecords);
    const visibleEvidenceIdList = visibleEvidence.map((row) => String(row.id));
    const evidenceIdPlaceholders = visibleEvidenceIdList.map(() => "?").join(",");

    const artifactSensitivity = sensitivitySql("a.sensitivity", access);
    const artifactEvidenceSensitivity = sensitivitySql("e.sensitivity", access);
    const artifactRows = visibleEvidenceIdList.length === 0
      ? []
      : this.#database.prepare(`
          SELECT DISTINCT a.id, a.artifact_type, a.content_hash, a.byte_size,
            a.media_type, a.sensitivity, a.storage_uri, a.created_at
          FROM artifacts a
          JOIN evidence e ON e.artifact_id = a.id
          WHERE e.run_id = ? AND e.mission_id = ?
            AND e.id IN (${evidenceIdPlaceholders})
            AND ${artifactSensitivity.sql} AND ${artifactEvidenceSensitivity.sql}
          ORDER BY a.created_at, a.id
          LIMIT ?
        `).all(
          runId,
          run.mission_id,
          ...visibleEvidenceIdList,
          ...artifactSensitivity.params,
          ...artifactEvidenceSensitivity.params,
          this.#maximumExportRecords + 1,
        ) as Row[];
    const visibleArtifacts = artifactRows.slice(0, this.#maximumExportRecords);
    const visibleArtifactIds = new Set(visibleArtifacts.map((row) => String(row.id)));

    const chainSensitivity = sensitivitySql("e.sensitivity", access);
    const chainRows = visibleEvidenceIdList.length === 0
      ? []
      : this.#database.prepare(`
          SELECT ce.id, ce.evidence_id, ce.event_type, ce.actor, ce.occurred_at
          FROM evidence_chain_events ce
          JOIN evidence e ON e.id = ce.evidence_id
          WHERE e.run_id = ? AND e.mission_id = ?
            AND e.id IN (${evidenceIdPlaceholders}) AND ${chainSensitivity.sql}
          ORDER BY ce.occurred_at, ce.id
          LIMIT ?
        `).all(
          runId,
          run.mission_id,
          ...visibleEvidenceIdList,
          ...chainSensitivity.params,
          this.#maximumExportRecords + 1,
        ) as Row[];
    const chain = chainRows.slice(0, this.#maximumExportRecords);

    const linkSensitivity = sensitivitySql("e.sensitivity", access);
    const findingLinkRows = visibleEvidenceIdList.length === 0
      ? []
      : this.#database.prepare(`
          SELECT fe.finding_id, fe.evidence_id, fe.relationship,
            f.title, f.severity, f.review_status
          FROM finding_evidence fe
          JOIN evidence e ON e.id = fe.evidence_id
          JOIN findings f ON f.id = fe.finding_id
          WHERE e.run_id = ? AND e.mission_id = ?
            AND e.id IN (${evidenceIdPlaceholders}) AND ${linkSensitivity.sql}
          ORDER BY f.updated_at, fe.finding_id, fe.evidence_id
          LIMIT ?
        `).all(
          runId,
          run.mission_id,
          ...visibleEvidenceIdList,
          ...linkSensitivity.params,
          this.#maximumExportRecords + 1,
        ) as Row[];
    const findingLinks = findingLinkRows.slice(0, this.#maximumExportRecords);

    const generatedAt = this.#clock().toISOString();
    const metadata = {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      exportKind: "run_evidence_metadata" as const,
      generatedAt,
      mission: {
        id: run.mission_id,
        name: boundedSanitized(run.mission_name),
        engagementId: run.engagement_id,
      },
      run: { id: run.id, journey: run.journey, status: run.status },
      evidence: visibleEvidence.map((row) => ({
        id: row.id,
        acquiredAt: row.acquired_at,
        source: boundedSanitized(row.source),
        target: boundedSanitized(row.target),
        evidenceType: row.evidence_type,
        contentHash: row.content_hash,
        confidence: row.confidence === null ? null : Number(row.confidence),
        sensitivity: row.sensitivity as OperationsSensitivity,
        verificationState: row.verification_state,
        summary: boundedSanitized(row.summary),
        artifactId: row.artifact_id && visibleArtifactIds.has(String(row.artifact_id))
          ? row.artifact_id
          : null,
        createdBy: boundedSanitized(row.created_by),
        createdAt: row.created_at,
      })),
      chainOfCustody: chain.map((row) => ({
        id: row.id,
        evidenceId: row.evidence_id,
        eventType: row.event_type,
        actor: boundedSanitized(row.actor),
        occurredAt: row.occurred_at,
      })),
      findingLinks: findingLinks.map((row) => ({
        findingId: row.finding_id,
        evidenceId: row.evidence_id,
        relationship: row.relationship,
        title: boundedSanitized(row.title),
        severity: row.severity,
        reviewStatus: row.review_status,
      })),
      artifacts: visibleArtifacts.map((row) => ({
        id: row.id,
        artifactType: row.artifact_type,
        contentHash: row.content_hash,
        byteSize: Number(row.byte_size),
        mediaType: row.media_type,
        sensitivity: row.sensitivity,
        storageScheme: /^([a-z][a-z0-9+.-]*):/iu.exec(String(row.storage_uri))?.[1]?.toLowerCase() ?? "unknown",
        createdAt: row.created_at,
      })),
      truncation: {
        evidence: evidenceRows.length > this.#maximumExportRecords,
        chainOfCustody: chainRows.length > this.#maximumExportRecords,
        findingLinks: findingLinkRows.length > this.#maximumExportRecords,
        artifacts: artifactRows.length > this.#maximumExportRecords,
      },
      privacy: {
        metadataOnly: true as const,
        omitted: [
          "raw evidence and extracted text",
          "provenance payloads and chain-event details",
          "artifact paths, URLs, metadata, and file contents",
          "provider, tool, authentication, and conversation payloads",
        ],
      },
    };
    const exported = {
      ...metadata,
      integrity: { algorithm: "sha256" as const, digest: sha256(canonicalJson(metadata)) },
    };
    this.#assertExportSize(exported);
    this.#appendAudit({
      missionId: run.mission_id,
      runId: run.id,
      journey: run.journey,
      actor,
      action: "evidence.bundle_exported",
      resourceType: "run",
      resourceId: run.id,
      reason: "Authorized operator exported a bounded redacted evidence metadata bundle.",
      details: {
        exportHash: exported.integrity.digest,
        evidenceCount: visibleEvidence.length,
        artifactCount: visibleArtifacts.length,
        truncation: exported.truncation,
        metadataOnly: true,
      },
      occurredAt: generatedAt,
    });
    return exported;
  }

  exportAuditRecords(
    runId: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
  ): Record<string, unknown> {
    if (!access.canExportAuditRecords) {
      throw forbidden("This identity cannot export immutable audit records.");
    }
    if (access.maximumSensitivity !== "restricted") {
      throw forbidden(
        "Audit-record exports require restricted-sensitivity access.",
        "Use a reviewer identity explicitly authorized for restricted operational audit data.",
      );
    }
    const run = this.#requireRun(runId, access);
    const rows = this.#database.prepare(`
      SELECT ar.id, ar.actor_type, ar.actor_id, ar.action, ar.resource_type,
        ar.resource_id, ar.reason, ar.details_json, ar.previous_hash,
        ar.record_hash, ar.occurred_at
      FROM audit_records ar
      WHERE ar.run_id = ? AND ar.mission_id = ?
      ORDER BY ar.occurred_at, ar.id
      LIMIT ?
    `).all(run.id, run.mission_id, this.#maximumExportRecords + 1) as Row[];
    const visible = rows.slice(0, this.#maximumExportRecords);
    const generatedAt = this.#clock().toISOString();
    const metadata = {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      exportKind: "run_audit_records" as const,
      generatedAt,
      mission: {
        id: run.mission_id,
        name: boundedSanitized(run.mission_name),
        engagementId: run.engagement_id,
      },
      run: { id: run.id, journey: run.journey, status: run.status },
      records: visible.map((row) => ({
        id: row.id,
        actorType: row.actor_type,
        actorId: boundedSanitized(row.actor_id),
        action: row.action,
        resourceType: row.resource_type,
        resourceId: row.resource_id,
        reason: boundedSanitized(row.reason),
        details: boundedSanitized(parseJson(
          typeof row.details_json === "string" ? row.details_json : null,
        )),
        previousHash: row.previous_hash,
        recordHash: row.record_hash,
        occurredAt: row.occurred_at,
      })),
      selection: {
        scope: "exact_run" as const,
        globalChainSubset: true as const,
        note: "The canonical audit chain is global; omitted records can make adjacent exported hashes non-contiguous.",
      },
      truncation: { records: rows.length > this.#maximumExportRecords },
      privacy: {
        redacted: true as const,
        omitted: [
          "audit records for other missions and runs",
          "credential-like values in reasons and details",
          "raw operational payloads not retained by the audit record",
        ],
      },
    };
    const exported = {
      ...metadata,
      integrity: { algorithm: "sha256" as const, digest: sha256(canonicalJson(metadata)) },
    };
    this.#assertExportSize(exported);
    this.#appendAudit({
      missionId: run.mission_id,
      runId: run.id,
      journey: run.journey,
      actor,
      action: "audit.records_exported",
      resourceType: "run",
      resourceId: run.id,
      reason: "Authorized reviewer exported a bounded redacted run-scoped audit record subset.",
      details: {
        exportHash: exported.integrity.digest,
        recordCount: visible.length,
        truncated: exported.truncation.records,
        restrictedAccessRequired: true,
      },
      occurredAt: generatedAt,
    });
    return exported;
  }

  #requireRun(runId: string, access: OperationsAccessPolicy): RunScopeRow {
    const scope = missionScopeSql("m", access);
    const run = this.#database.prepare(`
      SELECT r.id, r.mission_id, r.journey, r.status,
        m.name AS mission_name, m.engagement_id
      FROM runs r
      JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ? AND ${scope.sql}
    `).get(runId, ...scope.params) as RunScopeRow | undefined;
    if (!run) throw notFound("Run");
    return run;
  }

  #assertExportSize(exported: unknown): void {
    if (Buffer.byteLength(JSON.stringify(exported), "utf8") + 1 > this.#maximumExportBytes) {
      throw conflict(
        "The redacted export exceeds the configured response-size limit.",
        "Narrow the requested run or reduce retained metadata before retrying.",
      );
    }
  }

  #appendAudit(input: {
    readonly missionId: string;
    readonly runId: string | null;
    readonly journey: "autonomous" | "guided";
    readonly actor: OperationsActor;
    readonly action: string;
    readonly resourceType: string;
    readonly resourceId: string;
    readonly reason: string;
    readonly details: unknown;
    readonly occurredAt: string;
  }): void {
    inImmediateTransaction(this.#database, () => {
      const previous = this.#database.prepare(`
        SELECT record_hash FROM audit_records
        ORDER BY occurred_at DESC, id DESC LIMIT 1
      `).get() as { readonly record_hash: string } | undefined;
      const id = `audit_${randomUUID()}`;
      const details = boundedSanitized(input.details);
      const record = {
        id,
        missionId: input.missionId,
        runId: input.runId,
        journey: input.journey,
        actorType: input.actor.type,
        actorId: input.actor.id,
        action: input.action,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        reason: input.reason,
        details,
        previousHash: previous?.record_hash ?? null,
        occurredAt: input.occurredAt,
      };
      const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(record)}`);
      this.#database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json, previous_hash,
          record_hash, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        input.missionId,
        input.runId,
        input.journey,
        input.actor.type,
        input.actor.id,
        input.action,
        input.resourceType,
        input.resourceId,
        input.reason,
        canonicalJson(details),
        previous?.record_hash ?? null,
        recordHash,
        input.occurredAt,
      );
    });
  }
}
