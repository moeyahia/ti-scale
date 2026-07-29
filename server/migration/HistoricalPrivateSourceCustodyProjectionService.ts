import { createHash } from "node:crypto";
import { basename, isAbsolute, normalize, posix, relative, sep, win32 } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { digestCanonicalJson } from "../mcp/canonicalJson";

interface SourceOccurrenceRow {
  readonly source_reference: string;
  readonly source_hash: string;
  readonly modified_at: string;
  readonly byte_size: number;
  readonly classification: string;
  readonly object_kind: "accepted" | "quarantined" | "symlink" | "source";
  readonly source_path: string;
  readonly source_root: string;
  readonly registered_relative_path: string;
  readonly source_type: string;
  readonly source_identity: string;
  readonly registered_source_hash: string;
  readonly source_device: number;
  readonly source_inode: number;
  readonly registered_source_device: number | null;
  readonly registered_source_inode: number | null;
}

export interface HistoricalPrivateSourceBindingInput {
  readonly memorySourceId: string;
  readonly sourceCandidateId: string;
  readonly migrationId: string;
  readonly sourceReference: string;
  readonly sourceHash: string;
}

interface IndexedBindingInput extends HistoricalPrivateSourceBindingInput {
  readonly ordinal: number;
}

interface ResolvedSourceOccurrence extends SourceOccurrenceRow {
  readonly input: IndexedBindingInput;
  readonly sourceLocator: string;
}

interface PreparedBinding {
  readonly source: ResolvedSourceOccurrence;
  readonly projection: OriginProjection;
  readonly projectionCreatedAt: string | null;
  readonly createdAt: string;
  readonly receiptHash: string;
}

interface OriginProjection {
  readonly missionId: string;
  readonly runId: string;
  readonly artifactId: string;
  readonly bindingMethod: "existing_legacy_projection" | "private_source_projection";
}

export interface HistoricalPrivateSourceBindingResult extends OriginProjection {
  readonly memorySourceId: string;
  readonly sourceReference: string;
  readonly sourceHash: string;
  readonly sourceLocator: string;
  readonly created: boolean;
}

export interface HistoricalPrivateSourceBackfillResult {
  readonly migrationId: string;
  readonly selectedCount: number;
  readonly createdCount: number;
  readonly replayedCount: number;
  readonly hasMore: boolean;
}

const MAX_BINDINGS_PER_BATCH = 25_000;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableId(prefix: string, material: string): string {
  return `${prefix}_${sha256(material).slice(0, 48)}`;
}

function canonical(value: unknown): string {
  return digestCanonicalJson(value, { maxBytes: 64 * 1_024, maxDepth: 12 }).canonicalJson;
}

function safeStoredRelativePath(value: string): string {
  if (!value || value.includes("\0") || value.includes("\\")
      || isAbsolute(value) || win32.isAbsolute(value)) {
    throw new Error("Historical private source does not resolve inside its registered collection");
  }
  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")
      || posix.normalize(value) !== value) {
    throw new Error("Historical private source does not resolve inside its registered collection");
  }
  return value;
}

function canonicalAbsolutePath(value: string): string {
  if (!value || value.includes("\0") || !isAbsolute(value) || normalize(value) !== value) {
    throw new Error("Historical private source does not resolve inside its registered collection");
  }
  return value;
}

/**
 * Resolve the private display locator without consulting a mutable live file.
 *
 * Engagement inventories register a directory and accepted files below it.
 * Generic history inventories register one verified file as both the source
 * and source object. In that second representation `relative(root, file)` is
 * `.` by design, so the immutable, configured-root-relative `relative_path`
 * is the only useful locator. It is accepted only after the source/object
 * identity receipts prove that both rows describe the exact same file.
 */
function safeSourceLocator(source: SourceOccurrenceRow): string {
  const root = canonicalAbsolutePath(source.source_root);
  const sourcePath = canonicalAbsolutePath(source.source_path);
  if (source.source_identity !== sha256(`${source.source_type}\0${root}`)) {
    throw new Error("Historical private source conflicts with its registered source identity");
  }

  const result = relative(root, sourcePath).split(sep).join("/");
  if (result && result !== ".") {
    if (source.source_type !== "engagement_manifest" || source.object_kind !== "accepted") {
      throw new Error("Historical private source does not match its registered collection kind");
    }
    return safeStoredRelativePath(result);
  }

  if (root !== sourcePath || source.source_type === "engagement_manifest"
      || source.object_kind !== "source"
      || source.registered_source_hash !== source.source_hash
      || source.registered_source_device === null
      || source.registered_source_inode === null
      || source.registered_source_device !== source.source_device
      || source.registered_source_inode !== source.source_inode) {
    throw new Error("Historical private source does not match its immutable file-root custody");
  }
  const locator = safeStoredRelativePath(source.registered_relative_path);
  if (posix.basename(locator) !== basename(sourcePath)) {
    throw new Error("Historical private source locator conflicts with its registered file identity");
  }
  return locator;
}

function bindingKey(memorySourceId: string, sourceReference: string): string {
  return JSON.stringify([memorySourceId, sourceReference]);
}

/**
 * Projects exact historical file custody into private canonical records.
 *
 * This is intentionally not a memory-edge service. A reusable node remains
 * target-free while its memory_sources row can resolve, under operator access
 * control, to the exact private mission/run/artifact that owns the source
 * hash. Existing full legacy projections are reused; otherwise a minimal
 * terminal custody-only projection is created from immutable inventory data.
 */
export class HistoricalPrivateSourceCustodyProjectionService {
  readonly #clock: () => Date;

  constructor(
    private readonly database: SqliteDatabase,
    options: Readonly<{ clock?: () => Date }> = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
  }

  /** Older canonical databases remain usable until migration 034 is applied. */
  isAvailable(): boolean {
    return Boolean(this.database.prepare(`
      SELECT 1 AS present FROM sqlite_master
      WHERE type = 'table' AND name = 'historical_private_source_bindings'
    `).get());
  }

  /**
   * Deterministically repairs provenance rows confirmed before migration 034.
   * Selection is ordered and bounded; callers may replay until hasMore=false.
   */
  backfillMigration(migrationId: string, limit = 25_000): HistoricalPrivateSourceBackfillResult {
    if (!this.isAvailable()) {
      return { migrationId, selectedCount: 0, createdCount: 0, replayedCount: 0, hasMore: false };
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 25_000) {
      throw new Error("Historical private source backfill limit must be between 1 and 25000");
    }
    return inImmediateTransaction(this.database, () => {
      const rows = this.database.prepare(`
        SELECT memory_source.id AS memory_source_id,
          occurrence.candidate_id AS source_candidate_id,
          occurrence.migration_id, occurrence.source_reference,
          occurrence.source_hash
        FROM memory_sources memory_source
        JOIN historical_attack_knowledge_source_occurrences occurrence
          ON memory_source.source_type = 'historical_attack_knowledge_source_candidate'
         AND memory_source.source_id = occurrence.candidate_id || ':' || occurrence.migration_id
         AND memory_source.source_hash = occurrence.source_hash
        LEFT JOIN historical_private_source_bindings binding
          ON binding.memory_source_id = memory_source.id
         AND binding.source_reference = occurrence.source_reference
        WHERE occurrence.migration_id = ? AND binding.memory_source_id IS NULL
        ORDER BY memory_source.id, occurrence.source_reference
        LIMIT ?
      `).all(migrationId, limit + 1) as Array<{
        readonly memory_source_id: string;
        readonly source_candidate_id: string;
        readonly migration_id: string;
        readonly source_reference: string;
        readonly source_hash: string;
      }>;
      const selected = rows.slice(0, limit);
      const results = this.bindBatch(selected.map((row) => ({
          memorySourceId: row.memory_source_id,
          sourceCandidateId: row.source_candidate_id,
          migrationId: row.migration_id,
          sourceReference: row.source_reference,
          sourceHash: row.source_hash,
      })));
      return {
        migrationId,
        selectedCount: selected.length,
        createdCount: results.filter(({ created }) => created).length,
        replayedCount: results.filter(({ created }) => !created).length,
        hasMore: rows.length > limit,
      };
    });
  }

  /**
   * Resolve and project a bounded set of exact source origins as one atomic
   * operation. Results remain aligned with the caller's input order. A
   * repeated key behaves exactly like sequential bind calls: the first new
   * occurrence is created and later occurrences replay it.
   */
  bindBatch(
    inputs: readonly HistoricalPrivateSourceBindingInput[],
  ): readonly HistoricalPrivateSourceBindingResult[] {
    if (inputs.length === 0) return [];
    if (inputs.length > MAX_BINDINGS_PER_BATCH) {
      throw new Error(`Historical private source binding batch exceeds ${MAX_BINDINGS_PER_BATCH}`);
    }
    return inImmediateTransaction(this.database, () => {
      const unique: IndexedBindingInput[] = [];
      const firstByKey = new Map<string, IndexedBindingInput>();
      const keys = inputs.map((input, ordinal) => {
        const key = bindingKey(input.memorySourceId, input.sourceReference);
        const first = firstByKey.get(key);
        if (first) {
          if (first.sourceHash !== input.sourceHash) {
            throw new Error("Historical private source binding conflicts with immutable source custody");
          }
          return key;
        }
        const indexed = { ...input, ordinal };
        firstByKey.set(key, indexed);
        unique.push(indexed);
        return key;
      });

      const existing = this.#existingBindings(unique);
      const pending = unique.filter((input) => {
        const prior = existing.get(bindingKey(input.memorySourceId, input.sourceReference));
        if (prior && prior.sourceHash !== input.sourceHash) {
          throw new Error("Historical private source binding conflicts with immutable source custody");
        }
        return !prior;
      });
      const created = new Map<string, HistoricalPrivateSourceBindingResult>();
      if (pending.length > 0) {
        const sources = this.#sourceOccurrences(pending);
        const legacy = this.#existingLegacyProjections(sources);
        const prepared = this.#prepareBindings(sources, legacy);
        this.#materializePrivateProjections(prepared);
        this.#insertBindings(prepared);
        for (const item of prepared) {
          const { source, projection } = item;
          created.set(bindingKey(source.input.memorySourceId, source.input.sourceReference), {
            ...projection,
            memorySourceId: source.input.memorySourceId,
            sourceReference: source.source_reference,
            sourceHash: source.source_hash,
            sourceLocator: source.sourceLocator,
            created: true,
          });
        }
      }

      const emitted = new Set<string>();
      return keys.map((key) => {
        const prior = existing.get(key);
        if (prior) return prior;
        const result = created.get(key);
        if (!result) {
          throw new Error("Historical private source binding batch did not resolve every exact origin");
        }
        if (!emitted.has(key)) {
          emitted.add(key);
          return result;
        }
        return { ...result, created: false };
      });
    });
  }

  bind(input: Readonly<{
    memorySourceId: string;
    sourceCandidateId: string;
    migrationId: string;
    sourceReference: string;
    sourceHash: string;
  }>): HistoricalPrivateSourceBindingResult {
    return inImmediateTransaction(this.database, () => {
      const existing = this.#existingBinding(input.memorySourceId, input.sourceReference);
      if (existing) {
        if (existing.sourceHash !== input.sourceHash) {
          throw new Error("Historical private source binding conflicts with immutable source custody");
        }
        return existing;
      }

      const source = this.#sourceOccurrence(input);
      const sourceLocator = safeSourceLocator(source);
      const projection = this.#existingLegacyProjection(source, sourceLocator)
        ?? this.#ensurePrivateProjection(source, sourceLocator);
      const now = this.#clock().toISOString();
      const receipt = sha256(canonical({
        memorySourceId: input.memorySourceId,
        sourceCandidateId: input.sourceCandidateId,
        migrationId: input.migrationId,
        sourceReference: source.source_reference,
        sourceHash: source.source_hash,
        missionId: projection.missionId,
        runId: projection.runId,
        artifactId: projection.artifactId,
        bindingMethod: projection.bindingMethod,
      }));
      this.database.prepare(`
        INSERT INTO historical_private_source_bindings (
          memory_source_id, source_candidate_id, migration_id, source_reference,
          source_hash, mission_id, run_id, artifact_id, binding_method,
          binding_receipt_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        input.memorySourceId,
        input.sourceCandidateId,
        input.migrationId,
        source.source_reference,
        source.source_hash,
        projection.missionId,
        projection.runId,
        projection.artifactId,
        projection.bindingMethod,
        receipt,
        now,
      );
      return {
        ...projection,
        memorySourceId: input.memorySourceId,
        sourceReference: source.source_reference,
        sourceHash: source.source_hash,
        sourceLocator,
        created: true,
      };
    });
  }

  #existingBindings(
    inputs: readonly IndexedBindingInput[],
  ): Map<string, HistoricalPrivateSourceBindingResult> {
    if (inputs.length === 0) return new Map();
    const rows = this.database.prepare(`
      WITH requested AS MATERIALIZED (
        SELECT
          json_extract(value, '$.memorySourceId') AS memory_source_id,
          json_extract(value, '$.sourceReference') AS source_reference
        FROM json_each(?)
      )
      SELECT binding.memory_source_id, binding.source_reference,
        binding.source_hash, binding.mission_id, binding.run_id,
        binding.artifact_id, binding.binding_method,
        COALESCE(
          json_extract(artifact.metadata_json, '$.sourceLocator'),
          json_extract(artifact.metadata_json, '$.relativePath')
        ) AS source_locator
      FROM requested
      JOIN historical_private_source_bindings binding
        ON binding.memory_source_id = requested.memory_source_id
       AND binding.source_reference = requested.source_reference
      JOIN artifacts artifact ON artifact.id = binding.artifact_id
      ORDER BY binding.memory_source_id, binding.source_reference
    `).all(JSON.stringify(inputs)) as Array<{
      readonly memory_source_id: string;
      readonly source_reference: string;
      readonly source_hash: string;
      readonly mission_id: string;
      readonly run_id: string;
      readonly artifact_id: string;
      readonly binding_method: OriginProjection["bindingMethod"];
      readonly source_locator: string | null;
    }>;
    return new Map(rows.map((row) => [
      bindingKey(row.memory_source_id, row.source_reference),
      {
        memorySourceId: row.memory_source_id,
        sourceReference: row.source_reference,
        sourceHash: row.source_hash,
        sourceLocator: row.source_locator ?? "Protected historical source",
        missionId: row.mission_id,
        runId: row.run_id,
        artifactId: row.artifact_id,
        bindingMethod: row.binding_method,
        created: false,
      },
    ]));
  }

  #sourceOccurrences(
    inputs: readonly IndexedBindingInput[],
  ): readonly ResolvedSourceOccurrence[] {
    const rows = this.database.prepare(`
      WITH requested AS MATERIALIZED (
        SELECT
          CAST(json_extract(value, '$.ordinal') AS INTEGER) AS request_ordinal,
          json_extract(value, '$.memorySourceId') AS memory_source_id,
          json_extract(value, '$.sourceCandidateId') AS source_candidate_id,
          json_extract(value, '$.migrationId') AS migration_id,
          json_extract(value, '$.sourceReference') AS source_reference,
          json_extract(value, '$.sourceHash') AS source_hash
        FROM json_each(?)
      )
      SELECT requested.request_ordinal,
        occurrence.source_reference, occurrence.source_hash,
        occurrence.modified_at, source_object.byte_size,
        source_object.classification, source_object.object_kind,
        source_object.source_path,
        migration_source.source_path AS source_root,
        migration_source.relative_path AS registered_relative_path,
        migration_source.source_type, migration_source.source_identity,
        migration_source.source_sha256 AS registered_source_hash,
        source_object.source_device, source_object.source_inode,
        migration_source.source_device AS registered_source_device,
        migration_source.source_inode AS registered_source_inode
      FROM requested
      JOIN historical_attack_knowledge_source_occurrences occurrence
        ON occurrence.candidate_id = requested.source_candidate_id
       AND occurrence.migration_id = requested.migration_id
       AND occurrence.source_reference = requested.source_reference
       AND occurrence.source_hash = requested.source_hash
      JOIN legacy_migration_source_objects source_object
        ON source_object.migration_id = occurrence.migration_id
       AND source_object.source_reference = occurrence.source_reference
       AND source_object.source_sha256 = occurrence.source_hash
      JOIN legacy_migration_sources migration_source
        ON migration_source.id = source_object.source_id
       AND migration_source.migration_id = source_object.migration_id
      ORDER BY requested.request_ordinal,
        source_object.verified_at DESC, source_object.id ASC
    `).all(JSON.stringify(inputs)) as Array<SourceOccurrenceRow & {
      readonly request_ordinal: number;
    }>;
    const rowsByOrdinal = new Map<number, SourceOccurrenceRow[]>();
    for (const row of rows) {
      const list = rowsByOrdinal.get(Number(row.request_ordinal)) ?? [];
      list.push(row);
      rowsByOrdinal.set(Number(row.request_ordinal), list);
    }
    return inputs.map((input) => {
      const matches = rowsByOrdinal.get(input.ordinal) ?? [];
      if (matches.length !== 1) {
        throw new Error("Historical private source occurrence does not resolve to one immutable inventory object");
      }
      const source = matches[0]!;
      return {
        ...source,
        input,
        sourceLocator: safeSourceLocator(source),
      };
    });
  }

  #existingLegacyProjections(
    sources: readonly ResolvedSourceOccurrence[],
  ): Map<number, OriginProjection> {
    const hasManifestTable = this.database.prepare(`
      SELECT 1 AS present FROM sqlite_master
      WHERE type = 'table' AND name = 'legacy_engagement_manifests'
    `).get() as { readonly present: 1 } | undefined;
    if (!hasManifestTable || sources.length === 0) return new Map();
    const requested = sources.map((source) => ({
      ordinal: source.input.ordinal,
      sourceRoot: source.source_root,
      sourceHash: source.source_hash,
      sourceLocator: source.sourceLocator,
    }));
    const rows = this.database.prepare(`
      WITH requested AS MATERIALIZED (
        SELECT
          CAST(json_extract(value, '$.ordinal') AS INTEGER) AS request_ordinal,
          json_extract(value, '$.sourceRoot') AS source_root,
          json_extract(value, '$.sourceHash') AS source_hash,
          json_extract(value, '$.sourceLocator') AS source_locator
        FROM json_each(?)
      )
      SELECT requested.request_ordinal, manifest.mission_id,
        manifest.run_id, artifact.id AS artifact_id
      FROM requested
      JOIN legacy_engagement_manifests manifest
        ON manifest.source_path = requested.source_root
      JOIN artifacts artifact
        ON artifact.mission_id = manifest.mission_id
       AND artifact.run_id = manifest.run_id
       AND artifact.content_hash = requested.source_hash
       AND json_extract(artifact.metadata_json, '$.relativePath') = requested.source_locator
       AND artifact.sensitivity IN ('private', 'restricted')
      ORDER BY requested.request_ordinal, artifact.created_at DESC, artifact.id ASC
    `).all(JSON.stringify(requested)) as Array<{
      readonly request_ordinal: number;
      readonly mission_id: string;
      readonly run_id: string;
      readonly artifact_id: string;
    }>;
    const rowsByOrdinal = new Map<number, typeof rows>();
    for (const row of rows) {
      const ordinal = Number(row.request_ordinal);
      const list = rowsByOrdinal.get(ordinal) ?? [];
      list.push(row);
      rowsByOrdinal.set(ordinal, list);
    }
    const result = new Map<number, OriginProjection>();
    for (const source of sources) {
      const matches = rowsByOrdinal.get(source.input.ordinal) ?? [];
      if (matches.length > 1) {
        throw new Error("Historical private source resolves to multiple legacy artifacts");
      }
      const row = matches[0];
      if (row) {
        result.set(source.input.ordinal, {
          missionId: row.mission_id,
          runId: row.run_id,
          artifactId: row.artifact_id,
          bindingMethod: "existing_legacy_projection",
        });
      }
    }
    return result;
  }

  #prepareBindings(
    sources: readonly ResolvedSourceOccurrence[],
    legacy: ReadonlyMap<number, OriginProjection>,
  ): readonly PreparedBinding[] {
    return sources.map((source) => {
      const existingProjection = legacy.get(source.input.ordinal);
      const projectionCreatedAt = existingProjection ? null : this.#clock().toISOString();
      const projection = existingProjection ?? {
        missionId: stableId("mission_private_source", source.source_identity),
        runId: stableId("run_private_source", source.source_identity),
        artifactId: stableId(
          "artifact_private_source",
          `${source.source_identity}\0${source.sourceLocator}\0${source.source_hash}`,
        ),
        bindingMethod: "private_source_projection" as const,
      };
      const createdAt = this.#clock().toISOString();
      return {
        source,
        projection,
        projectionCreatedAt,
        createdAt,
        receiptHash: sha256(canonical({
          memorySourceId: source.input.memorySourceId,
          sourceCandidateId: source.input.sourceCandidateId,
          migrationId: source.input.migrationId,
          sourceReference: source.source_reference,
          sourceHash: source.source_hash,
          missionId: projection.missionId,
          runId: projection.runId,
          artifactId: projection.artifactId,
          bindingMethod: projection.bindingMethod,
        })),
      };
    });
  }

  #materializePrivateProjections(bindings: readonly PreparedBinding[]): void {
    const privateBindings = bindings.filter(({ projection }) => (
      projection.bindingMethod === "private_source_projection"
    ));
    if (privateBindings.length === 0) return;

    const collections = new Map<string, {
      readonly ordinal: number;
      readonly sourceIdentity: string;
      readonly missionId: string;
      readonly runId: string;
      readonly sourceModifiedAt: string;
      readonly createdAt: string;
    }>();
    const artifacts = new Map<string, {
      readonly ordinal: number;
      readonly artifactId: string;
      readonly missionId: string;
      readonly runId: string;
      readonly sourceReference: string;
      readonly sourceHash: string;
      readonly byteSize: number;
      readonly metadataJson: string;
      readonly createdAt: string;
    }>();
    for (const binding of privateBindings) {
      const { source, projection } = binding;
      if (!collections.has(source.source_identity)) {
        collections.set(source.source_identity, {
          ordinal: source.input.ordinal,
          sourceIdentity: source.source_identity,
          missionId: projection.missionId,
          runId: projection.runId,
          sourceModifiedAt: source.modified_at,
          createdAt: binding.projectionCreatedAt!,
        });
      }
      if (!artifacts.has(projection.artifactId)) {
        artifacts.set(projection.artifactId, {
          ordinal: source.input.ordinal,
          artifactId: projection.artifactId,
          missionId: projection.missionId,
          runId: projection.runId,
          sourceReference: source.source_reference,
          sourceHash: source.source_hash,
          byteSize: source.byte_size,
          metadataJson: canonical({
            sourceReference: source.source_reference,
            sourceLocator: source.sourceLocator,
            classification: source.classification,
            privateSourceCustodyOnly: true,
            reusableMemoryContent: false,
          }),
          createdAt: source.modified_at,
        });
      }
    }
    const collectionRows = [...collections.values()].sort((left, right) => left.ordinal - right.ordinal);
    const collectionJson = JSON.stringify(collectionRows);
    this.database.prepare(`
      WITH rows AS MATERIALIZED (
        SELECT
          CAST(json_extract(value, '$.ordinal') AS INTEGER) AS ordinal,
          json_extract(value, '$.sourceIdentity') AS source_identity,
          json_extract(value, '$.missionId') AS mission_id,
          json_extract(value, '$.runId') AS run_id,
          json_extract(value, '$.sourceModifiedAt') AS source_modified_at,
          json_extract(value, '$.createdAt') AS created_at
        FROM json_each(?)
      )
      INSERT OR IGNORE INTO missions (
        id, name, objective, journey, status, authorization_status,
        engagement_id, scope_json, success_criteria_json,
        retention_policy_json, memory_policy_json, created_by,
        version, created_at, updated_at, control_plane
      )
      SELECT mission_id,
        'Private historical source ' || substr(source_identity, 1, 12),
        'Retain access-controlled source custody without projecting target identity into reusable memory.',
        'guided', 'archived', 'unverified', NULL,
        json_object('privateSourceCustodyOnly', json('true'),
          'sourceIdentityReceipt', substr(source_identity, 1, 12)),
        '[]', json_object('preservePrivateSourceReference', json('true')),
        json_object('reusableProjection', json('false')),
        'system:historical-private-source-projection', 1,
        created_at, created_at, 'legacy'
      FROM rows ORDER BY ordinal
    `).run(collectionJson);
    this.database.prepare(`
      WITH rows AS MATERIALIZED (
        SELECT
          CAST(json_extract(value, '$.ordinal') AS INTEGER) AS ordinal,
          json_extract(value, '$.missionId') AS mission_id,
          json_extract(value, '$.runId') AS run_id,
          json_extract(value, '$.sourceModifiedAt') AS source_modified_at,
          json_extract(value, '$.createdAt') AS created_at
        FROM json_each(?)
      )
      INSERT OR IGNORE INTO runs (
        id, mission_id, journey, status, progress, status_reason,
        next_action_summary, budget_json, budget_usage_json,
        retry_count, replan_count, started_at, ended_at,
        created_at, updated_at, version, control_plane
      )
      SELECT run_id, mission_id, 'guided', 'completed', 1,
        'Private historical source custody projected',
        'No executable work; this run retains private provenance only.',
        '{}', '{}', 0, 0, source_modified_at, source_modified_at,
        created_at, created_at, 1, 'legacy'
      FROM rows ORDER BY ordinal
    `).run(collectionJson);
    this.database.prepare(`
      WITH rows AS MATERIALIZED (
        SELECT
          CAST(json_extract(value, '$.ordinal') AS INTEGER) AS ordinal,
          json_extract(value, '$.sourceIdentity') AS source_identity,
          json_extract(value, '$.missionId') AS mission_id,
          json_extract(value, '$.runId') AS run_id,
          json_extract(value, '$.createdAt') AS created_at
        FROM json_each(?)
      )
      INSERT OR IGNORE INTO historical_private_source_collections (
        source_identity, mission_id, run_id, created_at
      )
      SELECT source_identity, mission_id, run_id, created_at
      FROM rows ORDER BY ordinal
    `).run(collectionJson);
    const persistedCollections = this.database.prepare(`
      WITH requested AS MATERIALIZED (
        SELECT json_extract(value, '$.sourceIdentity') AS source_identity
        FROM json_each(?)
      )
      SELECT collection.source_identity, collection.mission_id, collection.run_id
      FROM requested
      JOIN historical_private_source_collections collection
        ON collection.source_identity = requested.source_identity
    `).all(collectionJson) as Array<{
      readonly source_identity: string;
      readonly mission_id: string;
      readonly run_id: string;
    }>;
    const persistedCollectionByIdentity = new Map(
      persistedCollections.map((row) => [row.source_identity, row]),
    );
    for (const expected of collectionRows) {
      const actual = persistedCollectionByIdentity.get(expected.sourceIdentity);
      if (!actual || actual.mission_id !== expected.missionId || actual.run_id !== expected.runId) {
        throw new Error("Historical private source collection conflicts with its stable identity");
      }
    }

    const artifactRows = [...artifacts.values()].sort((left, right) => left.ordinal - right.ordinal);
    const artifactJson = JSON.stringify(artifactRows);
    this.database.prepare(`
      WITH rows AS MATERIALIZED (
        SELECT
          CAST(json_extract(value, '$.ordinal') AS INTEGER) AS ordinal,
          json_extract(value, '$.artifactId') AS artifact_id,
          json_extract(value, '$.missionId') AS mission_id,
          json_extract(value, '$.runId') AS run_id,
          json_extract(value, '$.sourceReference') AS source_reference,
          json_extract(value, '$.sourceHash') AS source_hash,
          CAST(json_extract(value, '$.byteSize') AS INTEGER) AS byte_size,
          json_extract(value, '$.metadataJson') AS metadata_json,
          json_extract(value, '$.createdAt') AS created_at
        FROM json_each(?)
      )
      INSERT OR IGNORE INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json,
        created_at
      )
      SELECT artifact_id, mission_id, run_id, 'guided',
        'legacy_private_source_custody', source_reference, source_hash,
        byte_size, NULL, 'restricted', metadata_json, created_at
      FROM rows ORDER BY ordinal
    `).run(artifactJson);
    const persistedArtifacts = this.database.prepare(`
      WITH requested AS MATERIALIZED (
        SELECT json_extract(value, '$.artifactId') AS artifact_id
        FROM json_each(?)
      )
      SELECT artifact.id, artifact.mission_id, artifact.run_id,
        artifact.content_hash, artifact.sensitivity
      FROM requested JOIN artifacts artifact ON artifact.id = requested.artifact_id
    `).all(artifactJson) as Array<{
      readonly id: string;
      readonly mission_id: string;
      readonly run_id: string | null;
      readonly content_hash: string;
      readonly sensitivity: string;
    }>;
    const persistedArtifactById = new Map(persistedArtifacts.map((row) => [row.id, row]));
    for (const expected of artifactRows) {
      const actual = persistedArtifactById.get(expected.artifactId);
      if (!actual || actual.mission_id !== expected.missionId || actual.run_id !== expected.runId
          || actual.content_hash !== expected.sourceHash || actual.sensitivity !== "restricted") {
        throw new Error("Historical private source artifact conflicts with immutable source custody");
      }
    }
  }

  #insertBindings(bindings: readonly PreparedBinding[]): void {
    const rows = bindings.map(({ source, projection, receiptHash, createdAt }) => ({
      ordinal: source.input.ordinal,
      memorySourceId: source.input.memorySourceId,
      sourceCandidateId: source.input.sourceCandidateId,
      migrationId: source.input.migrationId,
      sourceReference: source.source_reference,
      sourceHash: source.source_hash,
      missionId: projection.missionId,
      runId: projection.runId,
      artifactId: projection.artifactId,
      bindingMethod: projection.bindingMethod,
      receiptHash,
      createdAt,
    }));
    this.database.prepare(`
      WITH rows AS MATERIALIZED (
        SELECT
          CAST(json_extract(value, '$.ordinal') AS INTEGER) AS ordinal,
          json_extract(value, '$.memorySourceId') AS memory_source_id,
          json_extract(value, '$.sourceCandidateId') AS source_candidate_id,
          json_extract(value, '$.migrationId') AS migration_id,
          json_extract(value, '$.sourceReference') AS source_reference,
          json_extract(value, '$.sourceHash') AS source_hash,
          json_extract(value, '$.missionId') AS mission_id,
          json_extract(value, '$.runId') AS run_id,
          json_extract(value, '$.artifactId') AS artifact_id,
          json_extract(value, '$.bindingMethod') AS binding_method,
          json_extract(value, '$.receiptHash') AS binding_receipt_hash,
          json_extract(value, '$.createdAt') AS created_at
        FROM json_each(?)
      )
      INSERT INTO historical_private_source_bindings (
        memory_source_id, source_candidate_id, migration_id, source_reference,
        source_hash, mission_id, run_id, artifact_id, binding_method,
        binding_receipt_hash, created_at
      )
      SELECT memory_source_id, source_candidate_id, migration_id,
        source_reference, source_hash, mission_id, run_id, artifact_id,
        binding_method, binding_receipt_hash, created_at
      FROM rows ORDER BY ordinal
    `).run(JSON.stringify(rows));
  }

  #existingBinding(
    memorySourceId: string,
    sourceReference: string,
  ): HistoricalPrivateSourceBindingResult | undefined {
    const row = this.database.prepare(`
      SELECT binding.memory_source_id, binding.source_reference,
        binding.source_hash, binding.mission_id, binding.run_id,
        binding.artifact_id, binding.binding_method,
        COALESCE(
          json_extract(artifact.metadata_json, '$.sourceLocator'),
          json_extract(artifact.metadata_json, '$.relativePath')
        ) AS source_locator
      FROM historical_private_source_bindings binding
      JOIN artifacts artifact ON artifact.id = binding.artifact_id
      WHERE binding.memory_source_id = ? AND binding.source_reference = ?
    `).get(memorySourceId, sourceReference) as {
      readonly memory_source_id: string;
      readonly source_reference: string;
      readonly source_hash: string;
      readonly mission_id: string;
      readonly run_id: string;
      readonly artifact_id: string;
      readonly binding_method: OriginProjection["bindingMethod"];
      readonly source_locator: string | null;
    } | undefined;
    if (!row) return undefined;
    return {
      memorySourceId: row.memory_source_id,
      sourceReference: row.source_reference,
      sourceHash: row.source_hash,
      sourceLocator: row.source_locator ?? "Protected historical source",
      missionId: row.mission_id,
      runId: row.run_id,
      artifactId: row.artifact_id,
      bindingMethod: row.binding_method,
      created: false,
    };
  }

  #sourceOccurrence(input: Readonly<{
    sourceCandidateId: string;
    migrationId: string;
    sourceReference: string;
    sourceHash: string;
  }>): SourceOccurrenceRow {
    const rows = this.database.prepare(`
      SELECT occurrence.source_reference, occurrence.source_hash,
        occurrence.modified_at, source_object.byte_size,
        source_object.classification, source_object.object_kind,
        source_object.source_path,
        migration_source.source_path AS source_root,
        migration_source.relative_path AS registered_relative_path,
        migration_source.source_type, migration_source.source_identity,
        migration_source.source_sha256 AS registered_source_hash,
        source_object.source_device, source_object.source_inode,
        migration_source.source_device AS registered_source_device,
        migration_source.source_inode AS registered_source_inode
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN legacy_migration_source_objects source_object
        ON source_object.migration_id = occurrence.migration_id
       AND source_object.source_reference = occurrence.source_reference
       AND source_object.source_sha256 = occurrence.source_hash
      JOIN legacy_migration_sources migration_source
        ON migration_source.id = source_object.source_id
       AND migration_source.migration_id = source_object.migration_id
      WHERE occurrence.candidate_id = ? AND occurrence.migration_id = ?
        AND occurrence.source_reference = ?
        AND occurrence.source_hash = ?
      ORDER BY source_object.verified_at DESC, source_object.id ASC
      LIMIT 2
    `).all(
      input.sourceCandidateId,
      input.migrationId,
      input.sourceReference,
      input.sourceHash,
    ) as SourceOccurrenceRow[];
    if (rows.length !== 1) {
      throw new Error("Historical private source occurrence does not resolve to one immutable inventory object");
    }
    return rows[0]!;
  }

  #existingLegacyProjection(
    source: SourceOccurrenceRow,
    sourceLocator: string,
  ): OriginProjection | undefined {
    const hasManifestTable = this.database.prepare(`
      SELECT 1 AS present FROM sqlite_master
      WHERE type = 'table' AND name = 'legacy_engagement_manifests'
    `).get() as { readonly present: 1 } | undefined;
    if (!hasManifestTable) return undefined;
    const rows = this.database.prepare(`
      SELECT manifest.mission_id, manifest.run_id, artifact.id AS artifact_id
      FROM legacy_engagement_manifests manifest
      JOIN artifacts artifact
        ON artifact.mission_id = manifest.mission_id
       AND artifact.run_id = manifest.run_id
      WHERE manifest.source_path = ?
        AND artifact.content_hash = ?
        AND json_extract(artifact.metadata_json, '$.relativePath') = ?
        AND artifact.sensitivity IN ('private', 'restricted')
      ORDER BY artifact.created_at DESC, artifact.id ASC
      LIMIT 2
    `).all(source.source_root, source.source_hash, sourceLocator) as Array<{
      readonly mission_id: string;
      readonly run_id: string;
      readonly artifact_id: string;
    }>;
    if (rows.length > 1) {
      throw new Error("Historical private source resolves to multiple legacy artifacts");
    }
    const row = rows[0];
    return row ? {
      missionId: row.mission_id,
      runId: row.run_id,
      artifactId: row.artifact_id,
      bindingMethod: "existing_legacy_projection",
    } : undefined;
  }

  #ensurePrivateProjection(
    source: SourceOccurrenceRow,
    sourceLocator: string,
  ): OriginProjection {
    const collectionKey = source.source_identity;
    const missionId = stableId("mission_private_source", collectionKey);
    const runId = stableId("run_private_source", collectionKey);
    const artifactId = stableId(
      "artifact_private_source",
      `${collectionKey}\0${sourceLocator}\0${source.source_hash}`,
    );
    const now = this.#clock().toISOString();
    const receiptLabel = collectionKey.slice(0, 12);
    this.database.prepare(`
      INSERT OR IGNORE INTO missions (
        id, name, objective, journey, status, authorization_status,
        engagement_id, scope_json, success_criteria_json,
        retention_policy_json, memory_policy_json, created_by,
        version, created_at, updated_at, control_plane
      ) VALUES (?, ?, ?, 'guided', 'archived', 'unverified', NULL, ?, '[]', ?, ?,
        'system:historical-private-source-projection', 1, ?, ?, 'legacy')
    `).run(
      missionId,
      `Private historical source ${receiptLabel}`,
      "Retain access-controlled source custody without projecting target identity into reusable memory.",
      canonical({ privateSourceCustodyOnly: true, sourceIdentityReceipt: receiptLabel }),
      canonical({ preservePrivateSourceReference: true }),
      canonical({ reusableProjection: false }),
      now,
      now,
    );
    this.database.prepare(`
      INSERT OR IGNORE INTO runs (
        id, mission_id, journey, status, progress, status_reason,
        next_action_summary, budget_json, budget_usage_json,
        retry_count, replan_count, started_at, ended_at,
        created_at, updated_at, version, control_plane
      ) VALUES (?, ?, 'guided', 'completed', 1,
        'Private historical source custody projected',
        'No executable work; this run retains private provenance only.',
        '{}', '{}', 0, 0, ?, ?, ?, ?, 1, 'legacy')
    `).run(runId, missionId, source.modified_at, source.modified_at, now, now);
    this.database.prepare(`
      INSERT OR IGNORE INTO historical_private_source_collections (
        source_identity, mission_id, run_id, created_at
      ) VALUES (?, ?, ?, ?)
    `).run(collectionKey, missionId, runId, now);
    this.#assertCollection(collectionKey, missionId, runId);
    this.database.prepare(`
      INSERT OR IGNORE INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json,
        created_at
      ) VALUES (?, ?, ?, 'guided', 'legacy_private_source_custody', ?, ?, ?,
        NULL, 'restricted', ?, ?)
    `).run(
      artifactId,
      missionId,
      runId,
      source.source_reference,
      source.source_hash,
      source.byte_size,
      canonical({
        sourceReference: source.source_reference,
        sourceLocator,
        classification: source.classification,
        privateSourceCustodyOnly: true,
        reusableMemoryContent: false,
      }),
      source.modified_at,
    );
    const artifact = this.database.prepare(`
      SELECT mission_id, run_id, content_hash, sensitivity
      FROM artifacts WHERE id = ?
    `).get(artifactId) as {
      readonly mission_id: string;
      readonly run_id: string | null;
      readonly content_hash: string;
      readonly sensitivity: string;
    } | undefined;
    if (!artifact || artifact.mission_id !== missionId || artifact.run_id !== runId
        || artifact.content_hash !== source.source_hash || artifact.sensitivity !== "restricted") {
      throw new Error("Historical private source artifact conflicts with immutable source custody");
    }
    return { missionId, runId, artifactId, bindingMethod: "private_source_projection" };
  }

  #assertCollection(sourceIdentity: string, missionId: string, runId: string): void {
    const collection = this.database.prepare(`
      SELECT mission_id, run_id FROM historical_private_source_collections
      WHERE source_identity = ?
    `).get(sourceIdentity) as {
      readonly mission_id: string;
      readonly run_id: string;
    } | undefined;
    if (!collection || collection.mission_id !== missionId || collection.run_id !== runId) {
      throw new Error("Historical private source collection conflicts with its stable identity");
    }
  }
}
