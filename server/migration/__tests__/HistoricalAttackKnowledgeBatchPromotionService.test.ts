import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { HistoricalAttackKnowledgeBatchPromotionService } from "../HistoricalAttackKnowledgeBatchPromotionService";
import { HistoricalAttackKnowledgeExtractionService } from "../HistoricalAttackKnowledgeExtractionService";
import type { LegacyEngagementFile, LegacyEngagementManifest } from "../LegacyEngagementDiscovery";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import { runHistoricalAttackPromotionCli } from "../historical-attack-promotion-cli";

const HMAC_KEY = "historical-attack-batch-promotion-key-more-than-32-bytes";
const NOW = "2026-07-20T20:00:00.000Z";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function setup(): { readonly directory: string; readonly database: SqliteDatabase; readonly databasePath: string } {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-batch-"));
  directories.push(directory);
  const databasePath = join(directory, "test.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  databases.push(database);
  migrateDatabase(database);
  return { directory, database, databasePath };
}

function manifest(
  root: string,
  definitions: readonly {
    readonly relativePath: string;
    readonly content: string;
    readonly kind?: LegacyEngagementFile["kind"];
  }[],
): LegacyEngagementManifest {
  const engagementName = "private-history-source";
  const engagementDirectory = join(root, engagementName);
  const files = definitions.map((definition) => {
    const absolutePath = join(engagementDirectory, definition.relativePath);
    mkdirSync(join(absolutePath, ".."), { recursive: true });
    writeFileSync(absolutePath, definition.content);
    const state = statSync(absolutePath);
    const bytes = Buffer.from(definition.content);
    const extension = extname(absolutePath).toLowerCase();
    return {
      absolutePath,
      relativePath: definition.relativePath,
      kind: definition.kind ?? "note",
      contentClass: [".json", ".xml", ".nmap", ".gnmap"].includes(extension) ? "structured" as const : "text" as const,
      mediaType: "text/plain",
      sha256: sha256(bytes),
      byteSize: bytes.byteLength,
      modifiedAt: state.mtime.toISOString(),
    } satisfies LegacyEngagementFile;
  });
  const engagementKey = sha256(`engagement\0${engagementName}`);
  return {
    id: `legacy_engagement_${engagementKey.slice(0, 40)}`,
    root,
    rootIdentity: "batch-test-device:batch-test-inode",
    engagementDirectory,
    engagementName,
    engagementKey,
    sha256: sha256(JSON.stringify(files.map(({ sha256: hash, byteSize, modifiedAt }) => ({ hash, byteSize, modifiedAt })))),
    byteSize: files.reduce((sum, file) => sum + file.byteSize, 0),
    modifiedAt: files.map(({ modifiedAt }) => modifiedAt).sort().at(-1)!,
    files,
    quarantined: [],
  };
}

function registerInventory(database: SqliteDatabase, source: LegacyEngagementManifest): void {
  const metadata = new MigrationMetadataRepository(database);
  metadata.ensureSchema();
  const run = metadata.createRun({
    sourceRoots: [source.root],
    databasePath: "test.sqlite",
    outputDirectory: "test-output",
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  const rootState = statSync(source.engagementDirectory);
  const sourceId = metadata.registerSource(run.id, {
    absolutePath: source.engagementDirectory,
    relativePath: source.engagementName,
    root: source.root,
    type: "engagement_manifest",
    sha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt,
  }, undefined, {
    retentionMode: "verified-reference",
    device: rootState.dev,
    inode: rootState.ino,
  });
  for (const file of source.files) {
    const state = statSync(file.absolutePath);
    metadata.registerSourceObject({
      migrationId: run.id,
      sourceId,
      objectKey: `accepted:${file.relativePath}`,
      sourcePath: file.absolutePath,
      objectKind: "accepted",
      classification: file.kind,
      sourceSha256: file.sha256,
      byteSize: file.byteSize,
      modifiedAt: file.modifiedAt,
      sourceDevice: state.dev,
      sourceInode: state.ino,
    });
  }
}

function stage(
  database: SqliteDatabase,
  source: LegacyEngagementManifest,
): HistoricalAttackKnowledgeExtractionService {
  registerInventory(database, source);
  const extractor = new HistoricalAttackKnowledgeExtractionService(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  });
  const result = extractor.extract(source);
  expect(result.compilerBundlesStaged).toBeGreaterThan(0);
  return extractor;
}

function stageWithoutInventory(
  database: SqliteDatabase,
  source: LegacyEngagementManifest,
): HistoricalAttackKnowledgeExtractionService {
  const extractor = new HistoricalAttackKnowledgeExtractionService(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  });
  const result = extractor.extract(source);
  expect(result.compilerBundlesStaged).toBeGreaterThan(0);
  return extractor;
}

function request() {
  return {
    actorId: "operator:historical-review",
    reason: "Approve this exact batch of objective, source-backed reusable facts.",
    maxRecords: 20,
    maxSourceBytes: 4 * 1024 * 1024,
    maxDurationMs: 30_000,
  } as const;
}

function safeFacts(prefix = "Apache HTTP Server/2.4.49"): string {
  return [
    `${prefix} path traversal was identified by an active service scan.`,
    "Encoded path normalization and directory traversal were observed together in the same bounded technical record.",
  ].join("\n");
}

function hashedV8FailureScript(options: {
  readonly exactVersion?: string;
  readonly outcome?: "failed" | "worked";
  readonly includeRecovery?: boolean;
} = {}): string {
  const version = options.exactVersion ? `V8 JavaScript engine ${options.exactVersion}. ` : "";
  const outcome = options.outcome ?? "failed";
  const recovery = options.includeRecovery === false
    ? ""
    : " Restart the service and require a health check before another bounded attempt.";
  return [
    "// Historical procedure record retained as an exact script artifact.",
    `// ${version}Harmony Set type confusion produced arbitrary read and arbitrary write before a WASM native-code foothold.`,
    `// This exact bounded procedure ${outcome} and the process crashed.${recovery}`,
    "export const reviewedProcedure = true;",
  ].join("\n");
}

describe("HistoricalAttackKnowledgeBatchPromotionService", () => {
  test("previews without writes then verifies sources and materializes connected objective facts", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [{ relativePath: "notes/apache.md", content: safeFacts() }]);
    stage(database, source);
    const service = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    });

    const preview = service.preview(request());
    expect(preview).toMatchObject({ stagedCount: 1, eligibleCount: 1, rejectedCount: 0 });
    expect(preview.review.entries[0]).toMatchObject({
      disposition: "eligible",
      knowledgeKind: "reusable_bundle",
    });
    expect(preview.review.entries[0]!.edgeCount).toBeGreaterThan(0);
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_batch_authorizations").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });

    const result = service.execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(result).toMatchObject({ status: "completed", stagedCount: 1, rejectedCount: 0, verifiedCount: 1, promotedCount: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE verification_state = 'verified'").get()).toEqual({ count: 1 });
    expect(Number((database.prepare("SELECT COUNT(*) AS count FROM memory_nodes WHERE lifecycle_status = 'verified'").get() as { count: number }).count)).toBeGreaterThan(3);
    expect(Number((database.prepare("SELECT COUNT(*) AS count FROM memory_edges WHERE lifecycle_status = 'verified'").get() as { count: number }).count)).toBeGreaterThan(2);
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_promotion_receipts").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_batch_reconciliations").get()).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action IN ('historical_attack_batch.authorized', 'historical_attack_batch.promoted')
    `).get()).toEqual({ count: 2 });

    const replay = service.execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(replay).toMatchObject({ status: "replayed", promotedCount: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_promotion_receipts").get()).toEqual({ count: 1 });
    expect(() => database.prepare(`
      UPDATE historical_attack_knowledge_batch_authorizations SET reason = 'changed'
    `).run()).toThrow(/immutable/iu);
  });

  test("keeps source-hash-bound historical failure claims unclassified until a canonical attempt is reviewed", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [{
      relativePath: "scripts/reviewed-v8-failure.js",
      content: hashedV8FailureScript({ exactVersion: "12.2.0" }),
      kind: "script",
    }]);
    stage(database, source);
    const service = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    });

    const preview = service.preview(request());
    expect(preview).toMatchObject({ stagedCount: 1, eligibleCount: 0, rejectedCount: 1 });
    expect(preview.review.entries[0]!.facts.some(({ nodeType }) => nodeType === "outcome")).toBe(true);
    expect(preview.review.entries[0]!.facts.some(({ nodeType }) => nodeType === "script_artifact")).toBe(true);
    expect(preview.review.entries[0]!.reasonCategories).toEqual(expect.arrayContaining([
      "human_judgment_required",
      "canonical_attack_attempt_outcome_required",
    ]));
    const result = service.execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(result).toMatchObject({ status: "completed", promotedCount: 0, verifiedCount: 0, rejectedCount: 1 });
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links",
    ).get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_nodes WHERE lifecycle_status = 'verified'
    `).get()).toEqual({ count: 0 });
  });

  test("rejects successful, narrative-only, unversioned, and custody-missing outcome claims", () => {
    const scenarios = [
      {
        name: "successful claim",
        content: hashedV8FailureScript({ exactVersion: "12.2.0", outcome: "worked", includeRecovery: false }),
        inventory: true,
      },
      {
        name: "narrative-only failed claim",
        content: [
          "V8 JavaScript engine 12.2.0.",
          "Harmony Set type confusion produced arbitrary read and arbitrary write before a WASM foothold.",
          "The bounded procedure failed and the process crashed.",
        ].join(" "),
        inventory: true,
      },
      {
        name: "unversioned script claim",
        content: hashedV8FailureScript(),
        inventory: true,
      },
      {
        name: "custody-missing script claim",
        content: hashedV8FailureScript({ exactVersion: "12.2.0" }),
        inventory: false,
      },
    ] as const;

    for (const [index, scenario] of scenarios.entries()) {
      const { directory, database } = setup();
      const source = manifest(directory, [{
        relativePath: scenario.name === "narrative-only failed claim"
          ? `notes/scenario-${index}.md`
          : `scripts/scenario-${index}.js`,
        content: scenario.content,
        kind: scenario.name === "narrative-only failed claim" ? "note" : "script",
      }]);
      scenario.inventory ? stage(database, source) : stageWithoutInventory(database, source);
      const preview = new HistoricalAttackKnowledgeBatchPromotionService(database, {
        receiptHmacKey: HMAC_KEY,
        clock: () => new Date(NOW),
      }).preview(request());
      expect(preview.rejectedCount, scenario.name).toBeGreaterThan(0);
      expect(preview.eligibleCount, scenario.name).toBe(0);
      expect(preview.review.entries.flatMap(({ reasonCategories }) => reasonCategories), scenario.name)
        .toContain("canonical_attack_attempt_outcome_required");
      if (!scenario.inventory) {
        expect(preview.review.entries.flatMap(({ reasonCategories }) => reasonCategories), scenario.name)
          .toContain("verified_source_custody_unavailable");
      }
    }
  });

  test("does not let a historical failed-outcome claim admit an unsupported CVE claim", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [{
      relativePath: "scripts/v8-failure-with-unreviewed-cve.js",
      content: `${hashedV8FailureScript({ exactVersion: "12.2.0" })}\n// CVE-2024-1939 was mentioned without authoritative applicability evidence.`,
      kind: "script",
    }]);
    stage(database, source);
    const preview = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    }).preview(request());

    expect(preview).toMatchObject({ stagedCount: 1, eligibleCount: 0, rejectedCount: 1 });
    expect(preview.review.entries[0]!.reasonCategories).toEqual(expect.arrayContaining([
      "human_judgment_required",
      "unsupported_objective_fact_type",
    ]));
  });

  test("never previews or promotes ambiguous address-shaped versions, contradictory OS builds, or product-bound identity procedures", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [{
      relativePath: "notes/version-and-identity-review.md",
      content: [
        "# Runtime inventory",
        "ASP.NET 100.92.5.83 appeared beside an endpoint locator.",
        "",
        "V8 JavaScript engine 12.2.281.1 was confirmed from local binary metadata.",
        "",
        "SQL injection appeared in an unrelated application note and was not reproduced.",
        "# Identity path",
        "V8 JavaScript engine 12.2.281.1 and NTLM relay were listed in the same broad inventory summary.",
        "# Operating system",
        "Windows Server 2016 Build 20348 was inconsistent, Windows Server 2022 Build 20348.4171 was corroborated, and Windows Server 2019 was observed without a build claim.",
      ].join("\n"),
    }]);
    stage(database, source);
    const service = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    });

    const preview = service.preview(request());
    expect(preview).toMatchObject({ stagedCount: 1, eligibleCount: 1, rejectedCount: 0 });
    const staged = JSON.stringify(database.prepare(`
      SELECT candidate_type, title, body FROM memory_candidates ORDER BY candidate_type, title
    `).all());
    expect(staged).not.toContain("100.92.5.83");
    expect(staged).not.toContain("100.92.5 build 83");
    expect(staged).not.toContain("NTLM relay procedure for V8 JavaScript engine");
    expect(staged).not.toContain("2016 Build 20348");
    expect(staged).toContain("V8 JavaScript engine 12.2.281.1");
    expect(staged).toContain("2022 Build 20348.4171");
    expect(staged).toContain('\\"exactVersion\\":\\"2019\\"');

    const result = service.execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(result).toMatchObject({ status: "completed", promotedCount: 1, rejectedCount: 0 });
    const promoted = JSON.stringify(database.prepare(`
      SELECT node_type, title, body FROM memory_nodes ORDER BY node_type, title
    `).all());
    expect(promoted).not.toContain("100.92.5.83");
    expect(promoted).not.toContain("NTLM relay procedure for V8 JavaScript engine");
    expect(promoted).not.toContain("2016 Build 20348");
    expect(promoted).toContain("V8 JavaScript engine 12.2.281.1");
    expect(promoted).toContain("2022 Build 20348.4171");
  });

  test("quarantines subjective applicability and withholds injected secret or target text", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [{
      relativePath: "notes/manual.md",
      content: `${safeFacts()}\nCVE-2021-41773 was mentioned.`,
    }]);
    stage(database, source);
    const candidate = database.prepare(`
      SELECT registry.candidate_id
      FROM attack_knowledge_candidate_registry registry
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      WHERE candidate.candidate_type = 'technology_product' LIMIT 1
    `).get() as { readonly candidate_id: string };
    database.prepare(`
      UPDATE memory_candidates
      SET title = 'target address 10.129.39.191 token=sk-test-unsafe-1234567890'
      WHERE id = ?
    `).run(candidate.candidate_id);
    database.prepare(`
      UPDATE memory_candidates SET candidate_type = 'preference'
      WHERE id = (
        SELECT registry.candidate_id
        FROM attack_knowledge_candidate_registry registry
        JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
        WHERE registry.candidate_id != ? AND candidate.candidate_type = 'attack_vector'
        LIMIT 1
      )
    `).run(candidate.candidate_id);
    database.prepare(`
      UPDATE attack_knowledge_bundles SET sanitized_bundle_json = sanitized_bundle_json || ' '
    `).run();
    const service = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    });
    const preview = service.preview(request());
    expect(preview.rejectedCount).toBe(1);
    expect(preview.review.entries[0]!.reasonCategories).toEqual(expect.arrayContaining([
      "human_judgment_required",
      "bundle_integrity_mismatch",
      "non_reusable_or_personal_memory",
      "secret_bearing_content",
      "target_or_engagement_identifier",
    ]));
    const serialized = JSON.stringify(preview);
    expect(serialized).not.toContain("10.129.39.191");
    expect(serialized).not.toContain("sk-test-unsafe");
    expect(serialized).toContain("[Rejected unsafe candidate]");

    const result = service.execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(result).toMatchObject({ status: "completed", rejectedCount: 1, verifiedCount: 0, promotedCount: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_batch_rejections").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_quarantine_records").get()).toEqual({ count: 1 });
  });

  test("fails source replacement closed and records a bounded rejection without following the link", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [{ relativePath: "notes/source-race.md", content: safeFacts() }]);
    stage(database, source);
    const service = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    });
    const preview = service.preview(request());
    expect(preview.eligibleCount).toBe(1);
    const sourcePath = source.files[0]!.absolutePath;
    renameSync(sourcePath, `${sourcePath}.moved`);
    symlinkSync(`${sourcePath}.moved`, sourcePath);

    const result = service.execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(result).toMatchObject({ status: "completed", rejectedCount: 1, verifiedCount: 0, promotedCount: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT reason_categories_json FROM historical_attack_knowledge_batch_rejections
    `).get()).toEqual({ reason_categories_json: '["source_custody_revalidation_failed"]' });
  });

  test("resumes the immutable authorization after a durable process interruption without duplicates", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [
      { relativePath: "notes/apache.md", content: safeFacts() },
      { relativePath: "notes/nginx.md", content: safeFacts("nginx 1.24") },
    ]);
    stage(database, source);
    const interrupting = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
      afterDurableItem: (count) => {
        if (count === 1) throw new Error("simulated process interruption");
      },
    });
    const preview = interrupting.preview(request());
    expect(preview).toMatchObject({ stagedCount: 2, eligibleCount: 2 });
    expect(() => interrupting.execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    })).toThrow("simulated process interruption");
    expect(database.prepare(`
      SELECT status, promoted_count FROM historical_attack_knowledge_batch_runs
    `).get()).toEqual({ status: "failed", promoted_count: 1 });

    const resumed = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    }).execute({
      ...request(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(resumed).toMatchObject({ status: "completed", stagedCount: 2, promotedCount: 2, verifiedCount: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_batch_authorizations").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_promotion_receipts").get()).toEqual({ count: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_batch_items WHERE disposition = 'promoted'").get()).toEqual({ count: 2 });
  });

  test("honors record and time budgets with cursor windows and same-receipt resume", () => {
    const { directory, database } = setup();
    const source = manifest(directory, [
      { relativePath: "notes/apache.md", content: safeFacts() },
      { relativePath: "notes/nginx.md", content: safeFacts("nginx 1.24") },
    ]);
    stage(database, source);
    const boundedRequest = { ...request(), maxRecords: 1, maxDurationMs: 1 };
    let tick = 0;
    const stopped = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
      monotonicNow: () => tick++ === 0 ? 0 : 2,
    });
    const preview = stopped.preview(boundedRequest);
    expect(preview.review).toMatchObject({ hasMore: true });
    expect(preview.review.nextSelectionCursor).toMatch(/^[a-f0-9]{64}$/u);
    const partial = stopped.execute({
      ...boundedRequest,
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(partial).toMatchObject({ status: "partial", promotedCount: 0 });
    expect(partial.nextResumeBundleFingerprint).toMatch(/^[a-f0-9]{64}$/u);

    const resumed = new HistoricalAttackKnowledgeBatchPromotionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
      monotonicNow: () => 0,
    }).execute({
      ...boundedRequest,
      expectedPreviewHash: preview.previewHash,
      acknowledgeObjectiveFactReview: true,
    });
    expect(resumed).toMatchObject({ status: "completed", promotedCount: 1 });
  });

  test("exposes a read-only preview and exact hash-bound run through the standalone CLI", async () => {
    const { directory, database, databasePath } = setup();
    const source = manifest(directory, [{ relativePath: "notes/cli.md", content: safeFacts() }]);
    stage(database, source);
    const output: string[] = [];
    const common = [
      "--db", databasePath,
      "--actor", request().actorId,
      "--reason", request().reason,
      "--max-records", String(request().maxRecords),
      "--max-bytes", String(request().maxSourceBytes),
      "--max-ms", String(request().maxDurationMs),
    ];
    expect(await runHistoricalAttackPromotionCli(
      ["preview", ...common, "--dry-run"],
      {},
      { write: (value) => output.push(value) },
    )).toBe(0);
    const preview = JSON.parse(output.join("")) as {
      readonly mode: string;
      readonly previewHash: string;
      readonly eligibleCount: number;
    };
    expect(preview).toMatchObject({ mode: "dry_run", eligibleCount: 1 });
    output.length = 0;
    expect(await runHistoricalAttackPromotionCli(
      [
        "run", ...common,
        "--expected-preview-hash", preview.previewHash,
        "--acknowledge-objective-fact-review",
      ],
      { TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY: HMAC_KEY },
      { write: (value) => output.push(value) },
    )).toBe(0);
    expect(JSON.parse(output.join(""))).toMatchObject({ status: "completed", promotedCount: 1 });
  });
});
