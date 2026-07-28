import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { OperationalTruthService } from "../../intelligence-v24/OperationalTruthService";
import type { OperationalHazardKnowledge } from "../AttackKnowledgeCompiler";
import {
  HistoricalHazardEvidenceImportInterruptedError,
  HistoricalHazardEvidenceImportService,
  type HistoricalHazardImportManifest,
} from "../HistoricalHazardEvidenceImportService";

const NOW = "2026-07-20T18:00:00.000Z";
const RECEIPT_KEY = "historical-hazard-import-test-key-at-least-32-bytes";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "historical-hazard-import-"));
  directories.push(directory);
  const sourceRoot = join(directory, "private-engagement");
  const backupRoot = join(directory, "protected-backup");
  const databasePath = join(directory, "state.sqlite");
  Bun.spawnSync(["mkdir", "-p", sourceRoot]);
  const database = createDatabaseConnection({ filename: databasePath });
  databases.push(database);
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, created_by, created_at, updated_at
    ) VALUES ('mission-private-history', 'Private imported history', 'Review authorized historical evidence',
      'guided', 'archived', 'verified', 'operator', ?, ?)
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
    VALUES ('run-private-history', 'mission-private-history', 'guided', 'completed', ?, ?)
  `).run(NOW, NOW);
  const service = new HistoricalHazardEvidenceImportService(database, {
    receiptHmacKey: RECEIPT_KEY,
    clock: () => new Date(NOW),
  });
  return { directory, sourceRoot, backupRoot, databasePath, database, service };
}

async function runCli(args: readonly string[]): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const process = Bun.spawn([
    globalThis.process.execPath,
    "run",
    "server/migration/cli.ts",
    ...args,
  ], {
    cwd: globalThis.process.cwd(),
    env: globalThis.process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  return { exitCode, stdout, stderr };
}

function sourceSelection(root: string, selectionId: string, filename: string, content: string, evidenceType: string) {
  const path = join(root, filename);
  writeFileSync(path, content, { mode: 0o600 });
  const state = statSync(path);
  return {
    selectionId,
    absolutePath: path,
    containmentRoot: root,
    sha256: sha256(content),
    byteSize: state.size,
    modifiedAt: state.mtime.toISOString(),
    evidenceType,
    label: `Private historical review item ${selectionId}`,
    meaning: "May support a reusable operational-hazard fact after independent review",
    mediaType: "text/plain",
  } as const;
}

function manifest(root: string): HistoricalHazardImportManifest {
  return {
    schemaVersion: 1,
    missionId: "mission-private-history",
    runId: "run-private-history",
    privateLabels: ["ReaperTwo", "10.129.39.191"],
    sources: [
      sourceSelection(
        root,
        "bounded-script",
        "bounded-script.js",
        "function boundedDiagnostic() { return 'health-check'; }\n",
        "generated_script_source",
      ),
      sourceSelection(
        root,
        "hang-observation",
        "private-hang-note.txt",
        "ReaperTwo at 10.129.39.191: harmless scalar worked; repeated diagnostic hung; reset restored service.\n",
        "operational_hazard_observation",
      ),
    ],
  };
}

function knowledge(scriptHash: string, observationHash: string): OperationalHazardKnowledge {
  return {
    kind: "operational_hazard",
    product: { name: "Microsoft Internet Information Services", exactVersion: "10.0" },
    stack: [
      { nodeType: "framework", name: "ASP.NET", exactVersion: "4.0.30319" },
      { nodeType: "runtime", name: "V8 JavaScript engine", exactVersion: "12.2.0" },
      { nodeType: "operating_system", name: "Windows Server", exactVersion: "2022 build 20348.4171" },
    ],
    procedure: {
      name: "Bounded internal-layout diagnostic",
      version: scriptHash,
      orderedSteps: [
        "Prove one harmless scalar expression completes",
        "Run one bounded diagnostic request",
        "Require a terminal marker before any later request",
      ],
      normalizedParameters: { automaticRetries: 0, concurrency: 1, requestTimeoutMs: 45_000 },
      prerequisites: ["Exact runtime versions match", "The harmless health check succeeds"],
    },
    scriptArtifacts: [{
      name: "Bounded layout diagnostic",
      version: `sha256:${scriptHash}`,
      contentHash: scriptHash,
      language: "JavaScript",
      purpose: "Performs one bounded diagnostic and emits a terminal marker",
    }],
    discoveries: [{
      name: "Base page and expression worker have separate health states",
      summary: "The base page can remain reachable while expression requests stop completing.",
      evidenceContentHashes: [observationHash],
    }],
    outcomes: [
      {
        name: "Harmless scalar health check completed",
        status: "worked",
        summary: "The harmless scalar probe completed before the diagnostic request.",
        evidenceContentHashes: [observationHash],
      },
      {
        name: "Repeated diagnostic request did not return",
        status: "failed",
        summary: "The expression worker stopped returning after the diagnostic sequence.",
        evidenceContentHashes: [observationHash],
        failureMode: "Expression worker retains an unfinished diagnostic request",
      },
    ],
    hazard: {
      name: "Expression worker stops returning after the bounded diagnostic sequence",
      observedSymptom: "The base page remains reachable while expression requests stop completing",
      affectedComponent: "Application expression worker",
      unaffectedComponents: ["Base HTTP request handler"],
      survivingHealthSignals: ["The base page continues returning a successful response"],
      stateBefore: "A harmless scalar expression completes",
      stateAfter: "Expression requests time out while the base page remains available",
      unsafeRetryConditions: ["The previous request has no terminal outcome"],
      healthGate: ["Restore a clean worker", "Require one harmless scalar result"],
      retryValidConditions: [
        "The prior diagnostic process is absent",
        "A fresh harmless scalar probe returns the expected value",
        "The next attempt uses a distinct reviewed procedure version",
      ],
      recoveryActionSummary: "Restore a clean worker and repeat only the harmless health check",
      recoveryCost: {
        exactProcedureResetCount: 1,
        operatorReportedResetCountMinimum: 11,
        requiresDisposableTargetReset: true,
      },
      saferAlternative: {
        name: "Offline single-stage layout review",
        orderedSteps: ["Inspect exact artifacts offline", "Run one non-printing calibration only after health passes"],
      },
      concurrencyMinimum: 1,
      timingWindowMs: 45_000,
    },
    corroboration: {
      exactProcedureAttemptCount: 1,
      exactProcedureReproducibilityCount: 1,
      exactProcedureEvidenceCount: 2,
    },
  };
}

function independentlyVerify(database: SqliteDatabase, candidateId: string, artifactId: string, hash: string) {
  const truth = new OperationalTruthService(database, { clock: () => new Date(NOW) });
  truth.promoteCandidate({
    candidateId,
    actor: { id: "operator-triage", type: "operator" },
    reason: "Selected for independent source and attribution validation",
  });
  return truth.verifyCandidate({
    candidateId,
    actor: { id: "operator-independent-reviewer", type: "operator" },
    reason: "Hash, provenance, source authenticity, and hazard attribution independently verified",
    source: "verified historical source review",
    target: "private historical evidence scope",
    acquiredAt: NOW,
    confidence: 1,
    provenance: {
      method: "independent verified-reference review",
      explanation: "Reviewer re-hashed the selected local source and compared it with the approved source identity.",
      sources: [{ kind: "artifact", id: artifactId }],
    },
    custody: [{ eventType: "acquired", actor: "operator-independent-reviewer", occurredAt: NOW }],
    satisfiedAdditionalRequirements: [
      "historical_source_authenticity_review",
      "operational_hazard_attribution_review",
    ],
    expectedContentHash: hash,
  });
}

describe("HistoricalHazardEvidenceImportService", () => {
  test("hazard-preview CLI performs bounded source verification without database writes", async () => {
    const { directory, sourceRoot, backupRoot, databasePath, database } = setup();
    const input = manifest(sourceRoot);
    const manifestPath = join(directory, "hazard-manifest.json");
    writeFileSync(manifestPath, `${JSON.stringify(input, null, 2)}\n`, { mode: 0o600 });

    const result = await runCli([
      "hazard-preview",
      "--db", databasePath,
      "--manifest", manifestPath,
    ]);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toMatchObject({
      dryRun: true,
      sourceCount: 2,
      privateLabelCount: 2,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_hazard_import_jobs").get())
      .toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 0 });
    expect(existsSync(backupRoot)).toBe(false);

    const rejected = await runCli([
      "hazard-preview",
      "--db", databasePath,
      "--manifest", manifestPath,
      "--backup-root", backupRoot,
    ]);
    expect(rejected.exitCode).toBe(1);
    expect(rejected.stderr).toContain("--backup-root is unavailable");
    expect(existsSync(backupRoot)).toBe(false);
  });

  test("dry-run writes nothing, stages private candidates only after exact approval, and resumes idempotently", () => {
    const { sourceRoot, backupRoot, database, service } = setup();
    const input = manifest(sourceRoot);
    const preview = service.preview(input);

    expect(preview).toMatchObject({ dryRun: true, sourceCount: 2, privateLabelCount: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_hazard_import_jobs").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 0 });
    expect(existsSync(backupRoot)).toBe(false);

    expect(() => service.stage({
      manifest: input,
      expectedPreviewHash: preview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
      interruptAfterSources: 1,
    })).toThrow(HistoricalHazardEvidenceImportInterruptedError);

    const interrupted = database.prepare(`
      SELECT id, status, checkpoint_ordinal FROM historical_hazard_import_jobs
    `).get() as { id: string; status: string; checkpoint_ordinal: number };
    expect(interrupted).toMatchObject({ status: "interrupted", checkpoint_ordinal: 1 });
    expect(existsSync(backupRoot)).toBe(false);

    const resumed = service.stage({
      manifest: input,
      expectedPreviewHash: preview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
    });
    expect(existsSync(backupRoot)).toBe(false);
    expect(resumed.status).toBe("candidates_staged");
    expect(resumed.candidateIds).toHaveLength(2);
    expect(resumed.artifactIds).toHaveLength(2);
    expect(resumed.reconciliation).toMatchObject({
      candidatesStaged: 2,
      candidatesPendingReview: 2,
      candidatesIndependentlyVerified: 0,
      artifactsPresent: 2,
      artifactHashMismatches: 0,
      sourceLinkMismatches: 0,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });
    expect((database.prepare(`
      SELECT storage_uri, metadata_json FROM artifacts ORDER BY id
    `).all() as Array<{ storage_uri: string; metadata_json: string }>).every((artifact) => (
      artifact.storage_uri.startsWith("historical-source-reference://")
      && JSON.parse(artifact.metadata_json).retentionMode === "verified-reference"
      && !artifact.metadata_json.includes("protectedBackupRef")
    ))).toBe(true);

    const replay = service.stage({
      manifest: input,
      expectedPreviewHash: preview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
    });
    expect(replay.status).toBe("replayed");
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 2 });
  });

  test("interrupted staging fails closed when a referenced source disappears and creates no recovery copy", () => {
    const { sourceRoot, backupRoot, database, service } = setup();
    const input = manifest(sourceRoot);
    const preview = service.preview(input);

    expect(() => service.stage({
      manifest: input,
      expectedPreviewHash: preview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
      interruptAfterSources: 1,
    })).toThrow(HistoricalHazardEvidenceImportInterruptedError);
    unlinkSync(input.sources[0]!.absolutePath);

    expect(() => service.stage({
      manifest: input,
      expectedPreviewHash: preview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
    })).toThrow();
    expect(existsSync(backupRoot)).toBe(false);
    expect(database.prepare(`
      SELECT status, checkpoint_ordinal FROM historical_hazard_import_jobs
    `).get()).toEqual({ status: "interrupted", checkpoint_ordinal: 1 });
  });

  test("binds only exact independently verified job evidence and stages a target-free script/discovery/outcome graph", () => {
    const { sourceRoot, database, service } = setup();
    const input = manifest(sourceRoot);
    const preview = service.preview(input);
    const staged = service.stage({
      manifest: input,
      expectedPreviewHash: preview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
    });
    const evidence = staged.candidateIds.map((candidateId, index) => independentlyVerify(
      database,
      candidateId,
      staged.artifactIds[index]!,
      input.sources[index]!.sha256,
    ));
    const richKnowledge = knowledge(input.sources[0]!.sha256, input.sources[1]!.sha256);
    const insufficientScriptSupport: OperationalHazardKnowledge = {
      ...richKnowledge,
      corroboration: {
        ...richKnowledge.corroboration,
        exactProcedureEvidenceCount: 1,
      },
    };

    expect(() => service.previewBundleBinding({
      jobId: staged.jobId,
      privateLabels: input.privateLabels,
      canonicalEvidenceIds: [evidence[1]!.id],
      knowledge: insufficientScriptSupport,
      confidence: 0.98,
    })).toThrow("canonical_evidence_support_missing");

    const bindingPreview = service.previewBundleBinding({
      jobId: staged.jobId,
      privateLabels: input.privateLabels,
      canonicalEvidenceIds: evidence.map(({ id }) => id),
      knowledge: richKnowledge,
      confidence: 0.98,
    });
    expect(bindingPreview).toMatchObject({ ready: true, dryRun: true });
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_bundles").get()).toEqual({ count: 0 });

    const bound = service.bindVerifiedEvidence({
      jobId: staged.jobId,
      privateLabels: input.privateLabels,
      canonicalEvidenceIds: evidence.map(({ id }) => id),
      knowledge: richKnowledge,
      confidence: 0.98,
      expectedBindingPreviewHash: bindingPreview.bindingPreviewHash,
      approvedBy: "operator-knowledge-reviewer",
      approvalGranted: true,
    });
    expect(bound.status).toBe("bundle_staged");
    expect(bound.reconciliation).toMatchObject({ candidatesIndependentlyVerified: 2, bundleId: bound.bundleId });
    const candidateTypes = (database.prepare(`
      SELECT registry.node_type FROM attack_knowledge_bundle_candidates linked
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = linked.content_fingerprint
      WHERE linked.bundle_id = ? ORDER BY registry.node_type
    `).all(bound.bundleId) as Array<{ node_type: string }>).map(({ node_type }) => node_type);
    expect(candidateTypes).toContain("script_artifact");
    expect(candidateTypes).toContain("discovery_pattern");
    expect(candidateTypes).toContain("outcome");
    expect(candidateTypes).toContain("failure_mode");
    expect(candidateTypes).toContain("attribute");
    expect(candidateTypes.filter((type) => type === "health_check").length).toBeGreaterThanOrEqual(3);
    const edgeTypes = (database.prepare(`
      SELECT edge_type FROM attack_knowledge_bundle_edges WHERE bundle_id = ?
    `).all(bound.bundleId) as Array<{ edge_type: string }>).map(({ edge_type }) => edge_type);
    expect(edgeTypes).toContain("implemented_by");
    expect(edgeTypes).toContain("tested_against");
    expect(edgeTypes).toContain("produces_outcome");
    expect(edgeTypes).toContain("failed_because");
    expect(edgeTypes).toContain("recovered_with");

    const reusableText = JSON.stringify({
      bundles: database.prepare("SELECT sanitized_bundle_json FROM attack_knowledge_bundles").all(),
      candidates: database.prepare(`
        SELECT title, summary, body FROM memory_candidates
      `).all(),
    });
    expect(reusableText).not.toContain("ReaperTwo");
    expect(reusableText).not.toContain("10.129.39.191");
    expect(reusableText).not.toContain("mission-private-history");
    expect(reusableText).not.toContain("run-private-history");
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get()).toEqual({ count: 0 });

    const replay = service.bindVerifiedEvidence({
      jobId: staged.jobId,
      privateLabels: input.privateLabels,
      canonicalEvidenceIds: evidence.map(({ id }) => id),
      knowledge: richKnowledge,
      confidence: 0.98,
      expectedBindingPreviewHash: bindingPreview.bindingPreviewHash,
      approvedBy: "operator-knowledge-reviewer",
      approvalGranted: true,
    });
    expect(replay.status).toBe("replayed");
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_hazard_import_bundle_links").get()).toEqual({ count: 1 });
  });

  test("rejects source substitution, preview drift, wrong private labels, and unrelated verified evidence", () => {
    const { sourceRoot, database, service } = setup();
    const input = manifest(sourceRoot);
    const preview = service.preview(input);
    writeFileSync(input.sources[0]!.absolutePath, "changed after preview\n");
    expect(() => service.stage({
      manifest: input,
      expectedPreviewHash: preview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
    })).toThrow("provenance");
    expect(database.prepare("SELECT COUNT(*) AS count FROM historical_hazard_import_jobs").get()).toEqual({ count: 0 });

    const fresh = manifest(sourceRoot);
    const freshPreview = service.preview(fresh);
    expect(() => service.stage({
      manifest: fresh,
      expectedPreviewHash: "f".repeat(64),
      approvedBy: "operator-reviewer",
      approvalGranted: true,
    })).toThrow("preview hash changed");
    const staged = service.stage({
      manifest: fresh,
      expectedPreviewHash: freshPreview.previewHash,
      approvedBy: "operator-reviewer",
      approvalGranted: true,
    });
    const evidence = staged.candidateIds.map((candidateId, index) => independentlyVerify(
      database,
      candidateId,
      staged.artifactIds[index]!,
      fresh.sources[index]!.sha256,
    ));
    expect(() => service.previewBundleBinding({
      jobId: staged.jobId,
      privateLabels: ["DifferentPrivateLabel"],
      canonicalEvidenceIds: evidence.map(({ id }) => id),
      knowledge: knowledge(fresh.sources[0]!.sha256, fresh.sources[1]!.sha256),
      confidence: 1,
    })).toThrow("Private labels do not match");
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type, content_hash,
        provenance_json, confidence, sensitivity, verification_state, summary, created_by, created_at
      ) VALUES ('evidence-unrelated', 'mission-private-history', 'run-private-history', 'other', ?,
        'private', 'artifact', ?, '{}', 1, 'restricted', 'verified', 'Unrelated', 'other-reviewer', ?)
    `).run(NOW, "d".repeat(64), NOW);
    database.prepare(`
      INSERT INTO evidence_chain_events (id, evidence_id, event_type, actor, occurred_at)
      VALUES ('custody-unrelated', 'evidence-unrelated', 'verified', 'other-reviewer', ?)
    `).run(NOW);
    expect(() => service.previewBundleBinding({
      jobId: staged.jobId,
      privateLabels: fresh.privateLabels,
      canonicalEvidenceIds: ["evidence-unrelated"],
      knowledge: knowledge(fresh.sources[0]!.sha256, fresh.sources[1]!.sha256),
      confidence: 1,
    })).toThrow("not an exact independently verified source from this import job");
  });
});
