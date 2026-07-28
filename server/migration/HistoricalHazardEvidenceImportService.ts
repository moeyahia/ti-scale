import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { CORE_EVIDENCE_REQUIREMENTS } from "../intelligence-v24/types";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import { canonicalJson } from "../orchestration/serialization";
import {
  AttackKnowledgeCompiler,
  type AttackKnowledgeCompileResult,
  type OperationalHazardKnowledge,
} from "./AttackKnowledgeCompiler";
import {
  verifyDiscoveredRegularSource,
  type DiscoveredRegularSource,
} from "./ProtectedBackupStore";

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SAFE_TYPE = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/u;
const MAX_SOURCES = 64;
const MAX_SOURCE_BYTES = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const PROPOSER_ID = "historical-hazard-importer";

export interface HistoricalHazardSourceSelection {
  readonly selectionId: string;
  readonly absolutePath: string;
  readonly containmentRoot: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly evidenceType: string;
  readonly label: string;
  readonly meaning: string;
  readonly mediaType?: string;
}

export interface HistoricalHazardImportManifest {
  readonly schemaVersion: 1;
  readonly missionId: string;
  readonly runId?: string;
  /** Private engagement/target labels used only by the reusable-memory leak scanner. */
  readonly privateLabels: readonly string[];
  readonly sources: readonly HistoricalHazardSourceSelection[];
}

interface NormalizedSource extends HistoricalHazardSourceSelection {
  readonly selectionKey: string;
}

interface NormalizedManifest extends Omit<HistoricalHazardImportManifest, "sources"> {
  readonly sources: readonly NormalizedSource[];
}

export interface HistoricalHazardImportPreview {
  readonly dryRun: true;
  readonly previewHash: string;
  readonly requestFingerprint: string;
  readonly sourceManifestHash: string;
  readonly sourceCount: number;
  readonly sourceBytes: number;
  readonly privateLabelCount: number;
  readonly sources: readonly {
    readonly selectionKey: string;
    readonly sha256: string;
    readonly byteSize: number;
    readonly modifiedAt: string;
    readonly evidenceType: string;
  }[];
}

export interface HistoricalHazardImportReconciliation {
  readonly jobId: string;
  readonly status: "staging" | "interrupted" | "candidates_staged" | "bundle_staged";
  readonly sourceCount: number;
  readonly sourceBytes: number;
  readonly checkpointOrdinal: number;
  readonly candidatesStaged: number;
  readonly candidatesPendingReview: number;
  readonly candidatesValidating: number;
  readonly candidatesIndependentlyVerified: number;
  readonly candidatesRejectedOrDemoted: number;
  readonly artifactsPresent: number;
  readonly artifactHashMismatches: number;
  readonly sourceLinkMismatches: number;
  readonly bundleId: string | null;
  readonly reconciliationHash: string;
}

export interface HistoricalHazardImportResult {
  readonly status: "candidates_staged" | "replayed";
  readonly jobId: string;
  readonly previewHash: string;
  readonly candidateIds: readonly string[];
  readonly artifactIds: readonly string[];
  readonly reconciliation: HistoricalHazardImportReconciliation;
}

export interface HistoricalHazardBindingPreview {
  readonly dryRun: true;
  readonly ready: boolean;
  readonly bindingPreviewHash: string;
  readonly jobId: string;
  readonly evidence: readonly {
    readonly id: string;
    readonly contentHash: string;
    readonly evidenceType: string;
    readonly acquiredAt: string;
  }[];
  readonly compiler: AttackKnowledgeCompileResult;
}

export interface HistoricalHazardBindingResult {
  readonly status: "bundle_staged" | "replayed";
  readonly jobId: string;
  readonly bundleId: string;
  readonly bindingPreviewHash: string;
  readonly canonicalEvidenceIds: readonly string[];
  readonly compiler: AttackKnowledgeCompileResult;
  readonly reconciliation: HistoricalHazardImportReconciliation;
}

interface JobRow {
  readonly id: string;
  readonly request_fingerprint: string;
  readonly preview_hash: string;
  readonly source_manifest_hash: string;
  readonly private_label_hashes_json: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly status: HistoricalHazardImportReconciliation["status"];
  readonly source_count: number;
  readonly source_bytes: number;
  readonly checkpoint_ordinal: number;
}

interface SourceRow {
  readonly ordinal: number;
  readonly selection_key: string;
  readonly source_hash: string;
  readonly byte_size: number;
  readonly modified_at: string;
  readonly evidence_type: string;
  readonly protected_backup_ref: string;
  readonly artifact_id: string | null;
  readonly candidate_id: string | null;
  readonly status: "pending" | "candidate_staged";
}

interface VerifiedEvidenceRow {
  readonly id: string;
  readonly content_hash: string;
  readonly evidence_type: string;
  readonly acquired_at: string;
  readonly source_hash: string;
  readonly modified_at: string;
}

function hash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function text(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be text`);
  const normalized = value.trim().normalize("NFKC");
  if (!normalized || normalized.length > maximum || /[\0]/u.test(normalized)) {
    throw new TypeError(`${label} must contain 1-${maximum} safe characters`);
  }
  return normalized;
}

function exactKeys(value: unknown, allowed: ReadonlySet<string>, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !allowed.has(key))) {
    throw new TypeError(`${label} contains an unsupported field`);
  }
  return record;
}

function iso(value: unknown, label: string): string {
  const parsed = Date.parse(text(value, label, 100));
  if (!Number.isFinite(parsed)) throw new TypeError(`${label} must be an ISO timestamp`);
  return new Date(parsed).toISOString();
}

function normalizeManifest(raw: unknown): NormalizedManifest {
  const manifest = exactKeys(raw, new Set([
    "schemaVersion", "missionId", "runId", "privateLabels", "sources",
  ]), "Historical hazard manifest");
  if (manifest.schemaVersion !== 1) throw new TypeError("Historical hazard manifest schemaVersion must be 1");
  const missionId = text(manifest.missionId, "missionId", 300);
  const runId = manifest.runId === undefined ? undefined : text(manifest.runId, "runId", 300);
  if (!Array.isArray(manifest.privateLabels) || manifest.privateLabels.length < 1 || manifest.privateLabels.length > 32) {
    throw new TypeError("privateLabels must select 1-32 private engagement labels");
  }
  const privateLabels = manifest.privateLabels.map((value, index) => text(value, `privateLabels[${index}]`, 300));
  if (new Set(privateLabels.map((value) => value.toLocaleLowerCase("en-US"))).size !== privateLabels.length) {
    throw new TypeError("privateLabels must be unique");
  }
  if (!Array.isArray(manifest.sources) || manifest.sources.length < 1 || manifest.sources.length > MAX_SOURCES) {
    throw new TypeError(`sources must select 1-${MAX_SOURCES} files`);
  }
  const sources = manifest.sources.map((rawSource, ordinal) => {
    const source = exactKeys(rawSource, new Set([
      "selectionId", "absolutePath", "containmentRoot", "sha256", "byteSize", "modifiedAt",
      "evidenceType", "label", "meaning", "mediaType",
    ]), `sources[${ordinal}]`);
    const selectionId = text(source.selectionId, `sources[${ordinal}].selectionId`, 128);
    if (!SAFE_ID.test(selectionId)) throw new TypeError("selectionId contains unsupported characters");
    const absolutePath = text(source.absolutePath, `sources[${ordinal}].absolutePath`, 4_096);
    const containmentRoot = text(source.containmentRoot, `sources[${ordinal}].containmentRoot`, 4_096);
    if (!isAbsolute(absolutePath) || !isAbsolute(containmentRoot)) {
      throw new TypeError("Historical source and containment root must be absolute paths");
    }
    const sha256 = text(source.sha256, `sources[${ordinal}].sha256`, 64).toLowerCase();
    if (!SHA256.test(sha256)) throw new TypeError("Historical source sha256 is invalid");
    if (!Number.isSafeInteger(source.byteSize) || Number(source.byteSize) < 0 || Number(source.byteSize) > MAX_SOURCE_BYTES) {
      throw new TypeError(`Historical source byteSize must be between 0 and ${MAX_SOURCE_BYTES}`);
    }
    const evidenceType = text(source.evidenceType, `sources[${ordinal}].evidenceType`, 128);
    if (!SAFE_TYPE.test(evidenceType) || evidenceType.toLocaleLowerCase("en-US") === "command_output") {
      throw new TypeError("Historical source evidenceType must be a non-command evidence class");
    }
    const normalized = {
      selectionId,
      absolutePath: resolve(absolutePath),
      containmentRoot: resolve(containmentRoot),
      sha256,
      byteSize: Number(source.byteSize),
      modifiedAt: iso(source.modifiedAt, `sources[${ordinal}].modifiedAt`),
      evidenceType,
      label: text(source.label, `sources[${ordinal}].label`, 500),
      meaning: text(source.meaning, `sources[${ordinal}].meaning`, 4_000),
      ...(source.mediaType === undefined ? {} : { mediaType: text(source.mediaType, `sources[${ordinal}].mediaType`, 200) }),
    };
    return {
      ...normalized,
      selectionKey: hash(canonicalJson({
        selectionId: normalized.selectionId,
        sha256: normalized.sha256,
        byteSize: normalized.byteSize,
        modifiedAt: normalized.modifiedAt,
        evidenceType: normalized.evidenceType,
      })),
    };
  });
  const total = sources.reduce((sum, source) => sum + source.byteSize, 0);
  if (total > MAX_TOTAL_BYTES) throw new TypeError(`Selected historical sources exceed ${MAX_TOTAL_BYTES} bytes`);
  if (new Set(sources.map(({ selectionId }) => selectionId)).size !== sources.length ||
      new Set(sources.map(({ selectionKey }) => selectionKey)).size !== sources.length) {
    throw new TypeError("Historical source selections must be unique");
  }
  return { schemaVersion: 1, missionId, ...(runId ? { runId } : {}), privateLabels, sources };
}

function discovered(source: NormalizedSource): DiscoveredRegularSource {
  return {
    absolutePath: source.absolutePath,
    containmentRoot: source.containmentRoot,
    sha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
  };
}

function manifestDigests(manifest: NormalizedManifest): {
  readonly preview: HistoricalHazardImportPreview;
  readonly privateLabelHashes: readonly string[];
} {
  const privateManifestJson = canonicalJson(manifest);
  const sourceManifestHash = hash(privateManifestJson);
  const privateLabelHashes = manifest.privateLabels
    .map((value) => hash(value.toLocaleLowerCase("en-US")))
    .sort();
  const publicSelection = manifest.sources.map((source) => ({
    selectionKey: source.selectionKey,
    sha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
    evidenceType: source.evidenceType,
  }));
  const requestFingerprint = hash(canonicalJson({
    schemaVersion: 1,
    missionId: manifest.missionId,
    runId: manifest.runId ?? null,
    sourceManifestHash,
    privateLabelHashes,
    sources: publicSelection,
  }));
  const sourceBytes = manifest.sources.reduce((sum, source) => sum + source.byteSize, 0);
  const previewHash = hash(canonicalJson({
    schemaVersion: 1,
    requestFingerprint,
    sourceManifestHash,
    privateLabelHashes,
    sourceCount: manifest.sources.length,
    sourceBytes,
    sources: publicSelection,
    canonicalEffects: ["artifact", "evidence_candidate"],
    automaticEffects: [],
  }));
  return {
    privateLabelHashes,
    preview: {
      dryRun: true,
      previewHash,
      requestFingerprint,
      sourceManifestHash,
      sourceCount: manifest.sources.length,
      sourceBytes,
      privateLabelCount: privateLabelHashes.length,
      sources: publicSelection,
    },
  };
}

export class HistoricalHazardEvidenceImportInterruptedError extends Error {
  constructor(readonly jobId: string, readonly checkpointOrdinal: number) {
    super("Historical hazard evidence staging was interrupted after a durable checkpoint");
    this.name = "HistoricalHazardEvidenceImportInterruptedError";
  }
}

/**
 * Private historical record -> canonical artifact/evidence-candidate staging.
 * It cannot verify evidence or promote reusable memory. The latter requires a
 * second, evidence-bound compiler call after OperationalTruthService review.
 */
export class HistoricalHazardEvidenceImportService {
  readonly #clock: () => Date;
  readonly #audit: AuditTrailWriter;
  readonly #receiptHmacKey?: Buffer;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly options: {
      readonly receiptHmacKey?: string | Buffer;
      readonly clock?: () => Date;
    },
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#audit = new AuditTrailWriter(database);
    this.#receiptHmacKey = options.receiptHmacKey === undefined
      ? undefined
      : Buffer.isBuffer(options.receiptHmacKey)
        ? Buffer.from(options.receiptHmacKey)
        : Buffer.from(options.receiptHmacKey, "utf8");
    if (this.#receiptHmacKey && this.#receiptHmacKey.byteLength < 32) {
      throw new TypeError("Historical hazard receipt HMAC key must contain at least 32 bytes");
    }
  }

  preview(rawManifest: unknown): HistoricalHazardImportPreview {
    const manifest = normalizeManifest(rawManifest);
    this.#assertCanonicalScope(manifest.missionId, manifest.runId);
    for (const source of manifest.sources) verifyDiscoveredRegularSource(discovered(source));
    return manifestDigests(manifest).preview;
  }

  stage(input: {
    readonly manifest: unknown;
    readonly expectedPreviewHash: string;
    readonly approvedBy: string;
    readonly approvalGranted: true;
    readonly interruptAfterSources?: number;
  }): HistoricalHazardImportResult {
    if (input.approvalGranted !== true) throw new Error("Explicit operator approval is required");
    const approvedBy = text(input.approvedBy, "approvedBy", 300);
    const manifest = normalizeManifest(input.manifest);
    this.#assertCanonicalScope(manifest.missionId, manifest.runId);
    const digests = manifestDigests(manifest);
    if (!SHA256.test(input.expectedPreviewHash) || input.expectedPreviewHash !== digests.preview.previewHash) {
      throw new Error("Historical hazard staging preview hash changed; review a fresh dry run");
    }
    const jobId = `hhij_${digests.preview.previewHash.slice(0, 40)}`;
    const existing = this.#jobByPreview(digests.preview.previewHash);
    if (existing && existing.id !== jobId) throw new Error("Historical hazard import identity mismatch");
    for (const source of manifest.sources) verifyDiscoveredRegularSource(discovered(source));
    if (existing?.status === "candidates_staged" || existing?.status === "bundle_staged") {
      return this.#result(existing, "replayed");
    }
    const now = this.#clock().toISOString();
    // The legacy column names are retained for schema compatibility, but the
    // values below are content-free references. No manifest or source bytes
    // are copied: every stage/replay re-verifies the operator-selected source.
    const verifiedManifestRef = `verified-reference-manifest:${digests.preview.sourceManifestHash}`;
    if (!existing) {
      inImmediateTransaction(this.database, () => {
        this.database.prepare(`
          INSERT INTO historical_hazard_import_jobs (
            id, request_fingerprint, preview_hash, source_manifest_hash,
            private_label_hashes_json, mission_id, run_id, status, source_count,
            source_bytes, checkpoint_ordinal, protected_manifest_ref,
            protected_manifest_hash, approved_by, approved_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 'staging', ?, ?, 0, ?, ?, ?, ?, ?, ?)
        `).run(
          jobId,
          digests.preview.requestFingerprint,
          digests.preview.previewHash,
          digests.preview.sourceManifestHash,
          canonicalJson(digests.privateLabelHashes),
          manifest.missionId,
          manifest.runId ?? null,
          manifest.sources.length,
          digests.preview.sourceBytes,
          verifiedManifestRef,
          digests.preview.sourceManifestHash,
          approvedBy,
          now,
          now,
          now,
        );
        const insert = this.database.prepare(`
          INSERT INTO historical_hazard_import_sources (
            job_id, ordinal, selection_key, source_hash, byte_size, modified_at,
            evidence_type, protected_backup_ref, status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        `);
        manifest.sources.forEach((source, ordinal) => insert.run(
          jobId,
          ordinal,
          source.selectionKey,
          source.sha256,
          source.byteSize,
          source.modifiedAt,
          source.evidenceType,
          `verified-reference:${source.selectionKey}`,
        ));
        this.#audit.append({
          missionId: manifest.missionId,
          ...(manifest.runId ? { runId: manifest.runId } : {}),
          actor: { id: approvedBy, type: "operator" },
          action: "historical_hazard_import.approved",
          resourceType: "historical_hazard_import_job",
          resourceId: jobId,
          reason: "Operator approved the exact bounded source manifest after dry-run review",
          details: {
            previewHash: digests.preview.previewHash,
            sourceManifestHash: digests.preview.sourceManifestHash,
            sourceCount: manifest.sources.length,
            sourceBytes: digests.preview.sourceBytes,
          },
          occurredAt: now,
        });
      });
    } else {
      this.#assertJobMatches(existing, digests.preview, digests.privateLabelHashes, manifest);
      this.database.prepare(`
        UPDATE historical_hazard_import_jobs SET status = 'staging', updated_at = ?
        WHERE id = ? AND status = 'interrupted'
      `).run(now, jobId);
    }

    const rows = this.#sourceRows(jobId);
    const journey = this.#missionJourney(manifest.missionId);
    for (const row of rows) {
      if (row.status === "candidate_staged") continue;
      const source = manifest.sources[row.ordinal];
      if (!source || source.selectionKey !== row.selection_key) {
        throw new Error("Historical hazard resume manifest does not match its durable checkpoint");
      }
      const verified = verifyDiscoveredRegularSource(discovered(source));
      if (verified.sha256 !== row.source_hash || verified.byteSize !== row.byte_size) {
        throw new Error("Historical source reference failed hash reconciliation");
      }
      const artifactId = `artifact_hh_${hash(`${jobId}\0${row.selection_key}`).slice(0, 40)}`;
      const candidateId = `candidate_hh_${hash(`${artifactId}\0candidate`).slice(0, 40)}`;
      const stagedAt = this.#clock().toISOString();
      inImmediateTransaction(this.database, () => {
        this.database.prepare(`
          INSERT INTO artifacts (
            id, mission_id, run_id, step_id, action_id, artifact_type, storage_uri,
            content_hash, byte_size, media_type, sensitivity, metadata_json, created_at, journey
          ) VALUES (?, ?, ?, NULL, NULL, 'historical_operational_hazard_source', ?, ?, ?, ?,
            'restricted', ?, ?, ?)
          ON CONFLICT(id) DO NOTHING
        `).run(
          artifactId,
          manifest.missionId,
          manifest.runId ?? null,
          `historical-source-reference://${row.selection_key}`,
          row.source_hash,
          row.byte_size,
          source.mediaType ?? null,
          canonicalJson({
            importJobId: jobId,
            selectionKey: row.selection_key,
            sourceHash: row.source_hash,
            sourceModifiedAt: row.modified_at,
            retentionMode: "verified-reference",
            sourceReference: row.protected_backup_ref,
          }),
          stagedAt,
          journey,
        );
        const artifact = this.database.prepare(`
          SELECT content_hash, byte_size FROM artifacts WHERE id = ?
        `).get(artifactId) as { readonly content_hash: string; readonly byte_size: number } | undefined;
        if (!artifact || artifact.content_hash !== row.source_hash || artifact.byte_size !== row.byte_size) {
          throw new Error("Historical hazard artifact idempotency collision");
        }
        this.database.prepare(`
          INSERT INTO evidence_candidates (
            id, mission_id, run_id, step_id, observation_id, artifact_id,
            evidence_type, label, meaning, promotion_reason,
            validation_requirements_json, state, sensitivity, proposed_by,
            reviewed_by, review_reason, promoted_evidence_id, created_at, reviewed_at
          ) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, 'candidate', 'restricted', ?,
            NULL, NULL, NULL, ?, NULL)
          ON CONFLICT(id) DO NOTHING
        `).run(
          candidateId,
          manifest.missionId,
          manifest.runId ?? null,
          artifactId,
          row.evidence_type,
          source.label,
          source.meaning,
          "Selected historical operational-hazard material requires independent evidence review",
          canonicalJson([
            ...CORE_EVIDENCE_REQUIREMENTS,
            "historical_source_authenticity_review",
            "operational_hazard_attribution_review",
          ]),
          PROPOSER_ID,
          stagedAt,
        );
        const candidate = this.database.prepare(`
          SELECT artifact_id, state, proposed_by FROM evidence_candidates WHERE id = ?
        `).get(candidateId) as {
          readonly artifact_id: string;
          readonly state: string;
          readonly proposed_by: string;
        } | undefined;
        if (!candidate || candidate.artifact_id !== artifactId || candidate.proposed_by !== PROPOSER_ID) {
          throw new Error("Historical hazard candidate idempotency collision");
        }
        this.database.prepare(`
          UPDATE historical_hazard_import_sources
          SET artifact_id = ?, candidate_id = ?, status = 'candidate_staged', staged_at = ?
          WHERE job_id = ? AND ordinal = ? AND status = 'pending'
        `).run(artifactId, candidateId, stagedAt, jobId, row.ordinal);
        this.database.prepare(`
          UPDATE historical_hazard_import_jobs
          SET checkpoint_ordinal = ?, updated_at = ? WHERE id = ?
        `).run(row.ordinal + 1, stagedAt, jobId);
        this.#audit.append({
          missionId: manifest.missionId,
          ...(manifest.runId ? { runId: manifest.runId } : {}),
          actor: { id: PROPOSER_ID, type: "system" },
          action: "historical_hazard_import.evidence_candidate_staged",
          resourceType: "evidence_candidate",
          resourceId: candidateId,
          reason: "Hash-verified source reference was staged for independent evidence review",
          details: {
            importJobId: jobId,
            selectionKey: row.selection_key,
            artifactId,
            sourceHash: row.source_hash,
            automaticVerification: false,
          },
          occurredAt: stagedAt,
        });
      });
      if (input.interruptAfterSources !== undefined && row.ordinal + 1 >= input.interruptAfterSources) {
        this.database.prepare(`
          UPDATE historical_hazard_import_jobs SET status = 'interrupted', updated_at = ? WHERE id = ?
        `).run(this.#clock().toISOString(), jobId);
        throw new HistoricalHazardEvidenceImportInterruptedError(jobId, row.ordinal + 1);
      }
    }
    const completedAt = this.#clock().toISOString();
    this.database.prepare(`
      UPDATE historical_hazard_import_jobs
      SET status = 'candidates_staged', checkpoint_ordinal = source_count,
          completed_at = ?, updated_at = ? WHERE id = ?
    `).run(completedAt, completedAt, jobId);
    return this.#result(this.#requireJob(jobId), "candidates_staged");
  }

  previewBundleBinding(input: {
    readonly jobId: string;
    readonly privateLabels: readonly string[];
    readonly canonicalEvidenceIds: readonly string[];
    readonly knowledge: OperationalHazardKnowledge;
    readonly confidence: number;
  }): HistoricalHazardBindingPreview {
    const compiler = this.#compiler();
    const job = this.#requireJob(text(input.jobId, "jobId", 300));
    if (job.status !== "candidates_staged" && job.status !== "bundle_staged") {
      throw new Error("Historical evidence candidates must finish staging before bundle review");
    }
    this.#assertPrivateLabels(job, input.privateLabels);
    const evidence = this.#verifiedEvidence(job.id, input.canonicalEvidenceIds);
    const compilerInput = this.#compilerInput(job, input.privateLabels, evidence, input.knowledge, input.confidence);
    const compilation = compiler.compile(compilerInput, { dryRun: true });
    if (compilation.status !== "dry_run" || !compilation.bundleId || !compilation.bundleFingerprint) {
      throw new Error(`Historical attack knowledge is not eligible: ${(compilation.reasonCategories ?? []).join(", ")}`);
    }
    const bindingPreviewHash = hash(canonicalJson({
      schemaVersion: 1,
      jobId: job.id,
      jobPreviewHash: job.preview_hash,
      bundleId: compilation.bundleId,
      bundleFingerprint: compilation.bundleFingerprint,
      evidence: evidence.map(({ id, content_hash, evidence_type, acquired_at }) => ({
        id,
        contentHash: content_hash,
        evidenceType: evidence_type,
        acquiredAt: acquired_at,
      })),
      confidence: input.confidence,
      automaticPromotion: false,
    }));
    return {
      dryRun: true,
      ready: true,
      bindingPreviewHash,
      jobId: job.id,
      evidence: evidence.map(({ id, content_hash, evidence_type, acquired_at }) => ({
        id,
        contentHash: content_hash,
        evidenceType: evidence_type,
        acquiredAt: acquired_at,
      })),
      compiler: compilation,
    };
  }

  bindVerifiedEvidence(input: {
    readonly jobId: string;
    readonly privateLabels: readonly string[];
    readonly canonicalEvidenceIds: readonly string[];
    readonly knowledge: OperationalHazardKnowledge;
    readonly confidence: number;
    readonly expectedBindingPreviewHash: string;
    readonly approvedBy: string;
    readonly approvalGranted: true;
  }): HistoricalHazardBindingResult {
    if (input.approvalGranted !== true) throw new Error("Explicit operator binding approval is required");
    const approvedBy = text(input.approvedBy, "approvedBy", 300);
    const job = this.#requireJob(text(input.jobId, "jobId", 300));
    const existing = this.database.prepare(`
      SELECT bundle_id, binding_preview_hash, evidence_ids_json
      FROM historical_hazard_import_bundle_links WHERE job_id = ?
    `).get(job.id) as {
      readonly bundle_id: string;
      readonly binding_preview_hash: string;
      readonly evidence_ids_json: string;
    } | undefined;
    if (existing) {
      if (existing.binding_preview_hash !== input.expectedBindingPreviewHash ||
          canonicalJson(JSON.parse(existing.evidence_ids_json)) !== canonicalJson([...input.canonicalEvidenceIds].sort())) {
        throw new Error("Historical hazard job is already linked to a different reviewed evidence set");
      }
      return {
        status: "replayed",
        jobId: job.id,
        bundleId: existing.bundle_id,
        bindingPreviewHash: existing.binding_preview_hash,
        canonicalEvidenceIds: JSON.parse(existing.evidence_ids_json) as string[],
        compiler: this.previewBundleBinding(input).compiler,
        reconciliation: this.reconcile(job.id),
      };
    }
    const preview = this.previewBundleBinding(input);
    if (!SHA256.test(input.expectedBindingPreviewHash) ||
        preview.bindingPreviewHash !== input.expectedBindingPreviewHash) {
      throw new Error("Historical attack-knowledge binding changed; review a fresh preview");
    }
    const evidence = this.#verifiedEvidence(job.id, input.canonicalEvidenceIds);
    const compiler = this.#compiler();
    const compiled = compiler.compile(
      this.#compilerInput(job, input.privateLabels, evidence, input.knowledge, input.confidence),
    );
    if (compiled.status !== "staged" || !compiled.bundleId || !compiled.provenanceReceiptId) {
      throw new Error(`Historical attack knowledge could not be staged: ${(compiled.reasonCategories ?? []).join(", ")}`);
    }
    const bundleId = compiled.bundleId;
    const provenanceReceiptId = compiled.provenanceReceiptId;
    const boundAt = this.#clock().toISOString();
    inImmediateTransaction(this.database, () => {
      this.database.prepare(`
        INSERT INTO historical_hazard_import_bundle_links (
          job_id, bundle_id, provenance_receipt_id, source_hash, binding_preview_hash,
          evidence_ids_json, actor_id, bound_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        job.id,
        bundleId,
        provenanceReceiptId,
        this.#bindingSourceHash(evidence),
        preview.bindingPreviewHash,
        canonicalJson(evidence.map(({ id }) => id).sort()),
        approvedBy,
        boundAt,
      );
      this.database.prepare(`
        UPDATE historical_hazard_import_jobs
        SET status = 'bundle_staged', updated_at = ?, completed_at = COALESCE(completed_at, ?)
        WHERE id = ? AND status = 'candidates_staged'
      `).run(boundAt, boundAt, job.id);
      this.#audit.append({
        missionId: job.mission_id,
        ...(job.run_id ? { runId: job.run_id } : {}),
        actor: { id: approvedBy, type: "operator" },
        action: "historical_hazard_import.verified_evidence_bound",
        resourceType: "attack_knowledge_bundle",
        resourceId: bundleId,
        reason: "Operator approved the exact independently verified evidence set for candidate bundle staging",
        details: {
          importJobId: job.id,
          bindingPreviewHash: preview.bindingPreviewHash,
          evidenceIds: evidence.map(({ id }) => id).sort(),
          automaticMemoryPromotion: false,
        },
        occurredAt: boundAt,
      });
    });
    return {
      status: "bundle_staged",
      jobId: job.id,
      bundleId,
      bindingPreviewHash: preview.bindingPreviewHash,
      canonicalEvidenceIds: evidence.map(({ id }) => id).sort(),
      compiler: compiled,
      reconciliation: this.reconcile(job.id),
    };
  }

  reconcile(jobId: string): HistoricalHazardImportReconciliation {
    const job = this.#requireJob(text(jobId, "jobId", 300));
    const counts = this.database.prepare(`
      SELECT
        COUNT(*) AS source_count,
        COALESCE(SUM(CASE WHEN imported.status = 'candidate_staged' THEN 1 ELSE 0 END), 0) AS staged,
        COALESCE(SUM(CASE WHEN candidate.state IN ('candidate') THEN 1 ELSE 0 END), 0) AS pending,
        COALESCE(SUM(CASE WHEN candidate.state = 'validating' THEN 1 ELSE 0 END), 0) AS validating,
        COALESCE(SUM(CASE WHEN candidate.state = 'promoted' AND canonical.verification_state = 'verified'
          AND EXISTS (SELECT 1 FROM evidence_chain_events custody WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified')
          THEN 1 ELSE 0 END), 0) AS verified,
        COALESCE(SUM(CASE WHEN candidate.state IN ('rejected', 'demoted') THEN 1 ELSE 0 END), 0) AS rejected,
        COALESCE(SUM(CASE WHEN artifact.id IS NOT NULL THEN 1 ELSE 0 END), 0) AS artifacts,
        COALESCE(SUM(CASE WHEN artifact.id IS NOT NULL AND (
          artifact.content_hash <> imported.source_hash OR artifact.byte_size <> imported.byte_size
        ) THEN 1 ELSE 0 END), 0) AS artifact_mismatches,
        COALESCE(SUM(CASE WHEN imported.status = 'candidate_staged' AND (
          artifact.id IS NULL OR candidate.id IS NULL OR candidate.artifact_id <> artifact.id
        ) THEN 1 ELSE 0 END), 0) AS source_link_mismatches
      FROM historical_hazard_import_sources imported
      LEFT JOIN artifacts artifact ON artifact.id = imported.artifact_id
      LEFT JOIN evidence_candidates candidate ON candidate.id = imported.candidate_id
      LEFT JOIN evidence canonical ON canonical.id = candidate.promoted_evidence_id
      WHERE imported.job_id = ?
    `).get(job.id) as Record<string, number>;
    const link = this.database.prepare(`
      SELECT bundle_id FROM historical_hazard_import_bundle_links WHERE job_id = ?
    `).get(job.id) as { readonly bundle_id: string } | undefined;
    const body = {
      jobId: job.id,
      status: job.status,
      sourceCount: job.source_count,
      sourceBytes: job.source_bytes,
      checkpointOrdinal: job.checkpoint_ordinal,
      candidatesStaged: Number(counts.staged),
      candidatesPendingReview: Number(counts.pending),
      candidatesValidating: Number(counts.validating),
      candidatesIndependentlyVerified: Number(counts.verified),
      candidatesRejectedOrDemoted: Number(counts.rejected),
      artifactsPresent: Number(counts.artifacts),
      artifactHashMismatches: Number(counts.artifact_mismatches),
      sourceLinkMismatches: Number(counts.source_link_mismatches),
      bundleId: link?.bundle_id ?? null,
    };
    return { ...body, reconciliationHash: hash(canonicalJson(body)) };
  }

  #compiler(): AttackKnowledgeCompiler {
    if (!this.#receiptHmacKey) {
      throw new Error("A server-only receipt HMAC key is required for attack-knowledge binding");
    }
    return new AttackKnowledgeCompiler(this.database, {
      receiptHmacKey: this.#receiptHmacKey,
      clock: this.#clock,
    });
  }

  #compilerInput(
    job: JobRow,
    privateLabels: readonly string[],
    evidence: readonly VerifiedEvidenceRow[],
    knowledge: OperationalHazardKnowledge,
    confidence: number,
  ) {
    const observedAt = evidence
      .map(({ modified_at }) => modified_at)
      .sort()
      .at(-1)!;
    const sourceHash = this.#bindingSourceHash(evidence);
    return {
      source: {
        privateSourceReference: `historical-hazard-import:${job.id}`,
        privateLabels,
        sourceClass: "historical" as const,
        sourceHash,
        observedAt,
        evidenceCount: evidence.length,
        canonicalEvidenceIds: evidence.map(({ id }) => id).sort(),
      },
      knowledge,
      confidence,
    };
  }

  #bindingSourceHash(evidence: readonly VerifiedEvidenceRow[]): string {
    return hash(canonicalJson(evidence.map(({ source_hash, id }) => ({
      id,
      sourceHash: source_hash,
    }))));
  }

  #verifiedEvidence(jobId: string, rawIds: readonly string[]): readonly VerifiedEvidenceRow[] {
    if (!Array.isArray(rawIds) || rawIds.length < 1 || rawIds.length > MAX_SOURCES) {
      throw new Error("Select 1-64 canonical evidence IDs");
    }
    const ids = rawIds.map((value, index) => text(value, `canonicalEvidenceIds[${index}]`, 300)).sort();
    if (new Set(ids).size !== ids.length) throw new Error("Canonical evidence IDs must be unique");
    const select = this.database.prepare(`
      SELECT canonical.id, canonical.content_hash, canonical.evidence_type, canonical.acquired_at,
        imported.source_hash, imported.modified_at
      FROM historical_hazard_import_sources imported
      JOIN evidence_candidates candidate ON candidate.id = imported.candidate_id
      JOIN evidence canonical ON canonical.id = candidate.promoted_evidence_id
      WHERE imported.job_id = ? AND canonical.id = ?
        AND candidate.state = 'promoted'
        AND canonical.verification_state = 'verified'
        AND lower(trim(canonical.evidence_type)) <> 'command_output'
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
        )
    `);
    return ids.map((id) => {
      const row = select.get(jobId, id) as VerifiedEvidenceRow | undefined;
      if (!row || !SHA256.test(row.content_hash) || row.content_hash !== row.source_hash) {
        throw new Error("Selected evidence is not an exact independently verified source from this import job");
      }
      return row;
    });
  }

  #assertPrivateLabels(job: JobRow, rawLabels: readonly string[]): void {
    if (!Array.isArray(rawLabels) || rawLabels.length < 1 || rawLabels.length > 32) {
      throw new Error("The original private labels are required for reusable-memory leak checking");
    }
    const labels = rawLabels.map((value, index) => text(value, `privateLabels[${index}]`, 300));
    const supplied = labels.map((value) => hash(value.toLocaleLowerCase("en-US"))).sort();
    const expected = JSON.parse(job.private_label_hashes_json) as string[];
    if (canonicalJson(supplied) !== canonicalJson(expected)) {
      throw new Error("Private labels do not match the reviewed historical source manifest");
    }
  }

  #assertCanonicalScope(missionId: string, runId?: string): void {
    if (!this.database.prepare("SELECT 1 FROM missions WHERE id = ?").get(missionId)) {
      throw new Error("Historical hazard import mission does not exist");
    }
    if (runId && !this.database.prepare("SELECT 1 FROM runs WHERE id = ? AND mission_id = ?").get(runId, missionId)) {
      throw new Error("Historical hazard import run does not belong to its mission");
    }
  }

  #missionJourney(missionId: string): "autonomous" | "guided" {
    const row = this.database.prepare("SELECT journey FROM missions WHERE id = ?")
      .get(missionId) as { readonly journey: "autonomous" | "guided" } | undefined;
    if (!row) throw new Error("Historical hazard import mission does not exist");
    return row.journey;
  }

  #jobByPreview(previewHash: string): JobRow | undefined {
    return this.database.prepare(`
      SELECT * FROM historical_hazard_import_jobs WHERE preview_hash = ?
    `).get(previewHash) as JobRow | undefined;
  }

  #requireJob(jobId: string): JobRow {
    const row = this.database.prepare(`
      SELECT * FROM historical_hazard_import_jobs WHERE id = ?
    `).get(jobId) as JobRow | undefined;
    if (!row) throw new Error("Historical hazard import job was not found");
    return row;
  }

  #sourceRows(jobId: string): readonly SourceRow[] {
    return this.database.prepare(`
      SELECT * FROM historical_hazard_import_sources WHERE job_id = ? ORDER BY ordinal
    `).all(jobId) as SourceRow[];
  }

  #assertJobMatches(
    job: JobRow,
    preview: HistoricalHazardImportPreview,
    privateLabelHashes: readonly string[],
    manifest: NormalizedManifest,
  ): void {
    if (job.request_fingerprint !== preview.requestFingerprint ||
        job.source_manifest_hash !== preview.sourceManifestHash ||
        job.mission_id !== manifest.missionId ||
        job.run_id !== (manifest.runId ?? null) ||
        job.source_count !== preview.sourceCount ||
        job.source_bytes !== preview.sourceBytes ||
        canonicalJson(JSON.parse(job.private_label_hashes_json)) !== canonicalJson(privateLabelHashes)) {
      throw new Error("Historical hazard resume manifest differs from the approved request");
    }
  }

  #result(job: JobRow, status: HistoricalHazardImportResult["status"]): HistoricalHazardImportResult {
    const sources = this.#sourceRows(job.id);
    return {
      status,
      jobId: job.id,
      previewHash: job.preview_hash,
      candidateIds: sources.flatMap(({ candidate_id }) => candidate_id ? [candidate_id] : []),
      artifactIds: sources.flatMap(({ artifact_id }) => artifact_id ? [artifact_id] : []),
      reconciliation: this.reconcile(job.id),
    };
  }
}

export { normalizeManifest as normalizeHistoricalHazardImportManifest };
