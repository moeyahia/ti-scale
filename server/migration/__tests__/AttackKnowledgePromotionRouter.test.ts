import { afterEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import {
  AttackKnowledgeCompiler,
  type OperationalHazardKnowledge,
} from "../AttackKnowledgeCompiler";
import {
  createAttackKnowledgePromotionRouter,
  type AttackKnowledgePromotionActor,
} from "../AttackKnowledgePromotionRouter";

const NOW = "2026-07-20T20:00:00.000Z";
const HMAC_KEY = "attack-knowledge-router-fixture-hmac-key-32-bytes";
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  databases.splice(0).forEach((database) => database.close());
});

function knowledge(): OperationalHazardKnowledge {
  return {
    kind: "operational_hazard",
    product: { name: "Microsoft IIS", exactVersion: "10.0" },
    stack: [{ nodeType: "runtime", name: "Embedded expression engine", exactVersion: "1.0" }],
    procedure: {
      name: "Bounded expression diagnostic sequence",
      version: "v3",
      orderedSteps: [
        "Run one harmless scalar execution probe",
        "Submit one bounded expression diagnostic",
        "Repeat the harmless scalar execution probe",
      ],
      normalizedParameters: { automaticRetries: 0, maximumDiagnosticStages: 1, healthProbeRequired: true },
      prerequisites: ["Base application page responds", "Expression execution health probe succeeds"],
    },
    hazard: {
      name: "Application execution path hangs after a known-bad diagnostic sequence",
      observedSymptom: "The base page remains reachable while expression requests stop completing",
      affectedComponent: "Application expression execution worker",
      stateBefore: "Harmless scalar execution probe succeeds",
      stateAfter: "Expression execution requests time out while the base page remains available",
      unsafeRetryConditions: ["The harmless expression health probe does not return"],
      healthGate: ["Recycle the isolated execution worker", "Prove a fresh harmless scalar probe succeeds"],
      recoveryActionSummary: "Recycle the application pool and pass the harmless execution health probe",
      recoveryCost: {
        exactProcedureResetCount: 2,
        operatorReportedResetCountMinimum: 11,
        serviceRecycleCount: 2,
      },
      saferAlternative: {
        name: "Single-stage expression validation",
        orderedSteps: ["Restore a healthy execution worker", "Run one lower-risk diagnostic stage"],
        reviewedBinding: {
          version: "v4-reviewed",
          normalizedParameters: {
            automaticRetries: 0,
            maximumDiagnosticStages: 1,
            healthProbeRequired: true,
          },
          sourceLoad: 1,
          sourceConcurrency: 1,
          sourceTimingWindowMs: 60_000,
          load: 1,
          concurrency: 1,
          timingWindowMs: 30_000,
        },
        retryConditionEvidence: [
          { statement: "Recycle the isolated execution worker", evidenceKey: "worker_recycled" },
          { statement: "Prove a fresh harmless scalar probe succeeds", evidenceKey: "scalar_probe_ok" },
        ],
      },
      concurrencyMinimum: 1,
      timingWindowMs: 120_000,
    },
    corroboration: {
      exactProcedureAttemptCount: 3,
      exactProcedureReproducibilityCount: 2,
      exactProcedureEvidenceCount: 2,
    },
  };
}

function bindApprovedHistoricalEvidencePath(
  database: SqliteDatabase,
  input: {
    readonly missionId: string;
    readonly runId: string;
    readonly bundleId: string;
    readonly provenanceReceiptId: string;
    readonly sourceHash: string;
    readonly evidenceIds: readonly string[];
  },
): void {
  const jobId = "historical-hazard-job-router-fixture";
  database.prepare(`
    INSERT INTO historical_hazard_import_jobs (
      id, request_fingerprint, preview_hash, source_manifest_hash,
      private_label_hashes_json, mission_id, run_id, status, source_count,
      source_bytes, checkpoint_ordinal, protected_manifest_ref,
      protected_manifest_hash, approved_by, approved_at, created_at,
      updated_at, completed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'candidates_staged', ?, ?, ?,
      'protected:historical-hazard-router-fixture', ?, 'operator-router', ?, ?, ?, ?)
  `).run(
    jobId,
    "3".repeat(64),
    "4".repeat(64),
    "5".repeat(64),
    JSON.stringify(["6".repeat(64)]),
    input.missionId,
    input.runId,
    input.evidenceIds.length,
    input.evidenceIds.length * 128,
    input.evidenceIds.length,
    "7".repeat(64),
    NOW,
    NOW,
    NOW,
    NOW,
  );
  input.evidenceIds.forEach((evidenceId, index) => {
    const evidence = database.prepare("SELECT content_hash FROM evidence WHERE id = ?")
      .get(evidenceId) as { readonly content_hash: string };
    const artifactId = `artifact-historical-hazard-router-${index}`;
    const candidateId = `candidate-historical-hazard-router-${index}`;
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, artifact_type, storage_uri, content_hash,
        byte_size, media_type, sensitivity, metadata_json, created_at, journey
      ) VALUES (?, ?, ?, 'historical_hazard_source', ?, ?, 128,
        'application/octet-stream', 'private', '{}', ?, 'guided')
    `).run(
      artifactId,
      input.missionId,
      input.runId,
      `protected:historical-hazard-router-source-${index}`,
      evidence.content_hash,
      NOW,
    );
    database.prepare(`
      INSERT INTO evidence_candidates (
        id, mission_id, run_id, artifact_id, evidence_type, label, meaning,
        promotion_reason, validation_requirements_json, state, sensitivity,
        proposed_by, reviewed_by, review_reason, promoted_evidence_id,
        created_at, reviewed_at
      ) VALUES (?, ?, ?, ?, 'finding_reproduction', 'Historical hazard source',
        'Independently reviewed source for the reusable hazard',
        'Operator approved the source and its canonical evidence', '[]',
        'promoted', 'private', 'historical-hazard-importer', 'operator-router',
        'Exact source review completed', ?, ?, ?)
    `).run(candidateId, input.missionId, input.runId, artifactId, evidenceId, NOW, NOW);
    database.prepare(`
      INSERT INTO historical_hazard_import_sources (
        job_id, ordinal, selection_key, source_hash, byte_size, modified_at,
        evidence_type, protected_backup_ref, artifact_id, candidate_id,
        status, staged_at
      ) VALUES (?, ?, ?, ?, 128, ?, 'finding_reproduction', ?, ?, ?,
        'candidate_staged', ?)
    `).run(
      jobId,
      index,
      String(index + 8).repeat(64),
      evidence.content_hash,
      NOW,
      `protected:historical-hazard-router-backup-${index}`,
      artifactId,
      candidateId,
      NOW,
    );
  });
  database.prepare(`
    INSERT INTO historical_hazard_import_bundle_links (
      job_id, bundle_id, provenance_receipt_id, source_hash,
      binding_preview_hash, evidence_ids_json, actor_id, bound_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'operator-router', ?)
  `).run(
    jobId,
    input.bundleId,
    input.provenanceReceiptId,
    input.sourceHash,
    "d".repeat(64),
    JSON.stringify([...input.evidenceIds].sort()),
    NOW,
  );
}

function fixture(bindEvidence = true) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const missionId = "mission-private-router-review";
  const runId = "run-private-router-review";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Private router fixture', 'Review generalized reusable memory',
      'guided', 'completed', 'verified', '{}', 'operator-router', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'guided', 'completed', 1, 'Review complete', '{}', '{}', ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, NOW, NOW);

  const evidenceIds = [
    "evidence-ReaperTwo-10.129.39.191-private-reset-proof",
    "evidence-private-health-gate-proof",
  ] as const;
  for (const [index, evidenceId] of evidenceIds.entries()) {
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (?, ?, ?, 'trusted-local-evaluator', ?, 'private-target-redacted',
        'finding_reproduction', ?, '{"method":"local_evaluator"}', 1,
        'private', 'verified', 'Private canonical reproduction evidence',
        'local-evidence-verifier', ?)
    `).run(evidenceId, missionId, runId, NOW, String(index + 1).repeat(64), NOW);
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', 'local-evidence-verifier', '{}', ?)
    `).run(`custody-${index}`, evidenceId, NOW);
  }

  const compiler = new AttackKnowledgeCompiler(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  });
  const compiled = compiler.compile({
    source: {
      privateSourceReference: "/root/private/ReaperTwo/10.129.39.191.md",
      privateLabels: ["ReaperTwo", "10.129.39.191"],
      sourceClass: "historical",
      sourceHash: "a".repeat(64),
      observedAt: NOW,
      evidenceCount: 8,
      ...(bindEvidence ? { canonicalEvidenceIds: evidenceIds } : {}),
    },
    knowledge: knowledge(),
    confidence: 0.96,
  });
  if (!compiled.bundleId || !compiled.bundleFingerprint) throw new Error("Router fixture failed to stage a bundle");
  if (bindEvidence) {
    if (!compiled.provenanceReceiptId) throw new Error("Router fixture did not create a provenance receipt");
    bindApprovedHistoricalEvidencePath(database, {
      missionId,
      runId,
      bundleId: compiled.bundleId,
      provenanceReceiptId: compiled.provenanceReceiptId,
      sourceHash: "a".repeat(64),
      evidenceIds,
    });
  }
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const candidates = database.prepare(`
    SELECT registry.candidate_id AS candidateId
    FROM attack_knowledge_bundle_candidates linked
    JOIN attack_knowledge_candidate_registry registry
      ON registry.content_fingerprint = linked.content_fingerprint
    WHERE linked.bundle_id = ? ORDER BY linked.ordinal
  `).all(compiled.bundleId) as Array<{ candidateId: string }>;
  for (const { candidateId } of candidates) memory.confirmCandidate(candidateId, "operator-router", {});
  return { database, compiled, evidenceIds, candidateCount: candidates.length };
}

async function harness(input: {
  readonly database: SqliteDatabase;
  readonly actor?: AttackKnowledgePromotionActor;
  readonly authorize?: boolean;
  readonly authorizeEvidence?: boolean;
}) {
  let actor = input.actor;
  let authorize = input.authorize ?? true;
  let authorizeEvidence = input.authorizeEvidence ?? true;
  const app = express();
  app.use(express.json({ limit: "32kb", strict: true }));
  app.use(createAttackKnowledgePromotionRouter({
    database: input.database,
    resolveActor: () => actor,
    authorize: () => authorize,
    authorizeEvidence: () => authorizeEvidence,
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    setActor: (next?: AttackKnowledgePromotionActor) => { actor = next; },
    setAuthorize: (next: boolean) => { authorize = next; },
    setAuthorizeEvidence: (next: boolean) => { authorizeEvidence = next; },
  };
}

describe("authenticated attack-knowledge promotion API", () => {
  test("lists only generalized review metadata and offers the exact compiler-bound evidence set", async () => {
    const { database, compiled, evidenceIds, candidateCount } = fixture();
    const application = await harness({ database, actor: { id: "operator-router", type: "operator" } });
    const listResponse = await fetch(`${application.origin}/api/v2/brain/attack-knowledge/bundles?status=all`);
    expect(listResponse.status).toBe(200);
    expect(listResponse.headers.get("cache-control")).toBe("private, no-store");
    const page = await listResponse.json() as any;
    expect(page).toMatchObject({
      schemaVersion: "2.4",
      totalReturned: 1,
      items: [{
        bundleId: compiled.bundleId,
        bundleFingerprint: compiled.bundleFingerprint,
        status: "staged",
        kind: "operational_hazard",
        candidates: { total: candidateCount, reviewed: candidateCount, pending: 0, rejected: 0 },
        boundEvidenceCount: 2,
        exactProcedureCounts: {
          attempts: 3,
          reproducibleOutcomes: 2,
          evidenceItems: 2,
          exactResets: 2,
          operatorReportedAggregateResetMinimum: 11,
        },
      }],
    });
    const reusableListText = JSON.stringify(page);
    expect(reusableListText).not.toContain("ReaperTwo");
    expect(reusableListText).not.toContain("10.129.39.191");
    expect(reusableListText).not.toContain("/root/private");

    const evidenceResponse = await fetch(
      `${application.origin}/api/v2/brain/attack-knowledge/bundles/${compiled.bundleFingerprint}/evidence`,
    );
    expect(evidenceResponse.status).toBe(200);
    const evidence = await evidenceResponse.json() as any;
    expect(evidence.items.map(({ id }: { id: string }) => id)).toEqual([...evidenceIds]);
    expect(Object.keys(evidence.items[0]).sort()).toEqual([
      "acquiredAt", "contentHash", "evidenceType", "id", "verificationState",
    ]);
    expect(JSON.stringify(evidence)).not.toContain("private-target-redacted");
    expect(JSON.stringify(evidence)).not.toContain("mission-private-router-review");
    expect(JSON.stringify(evidence)).not.toContain("run-private-router-review");
  });

  test("fails closed for absent authority, reviewer authority, or inaccessible private evidence", async () => {
    const { database, compiled } = fixture();
    const application = await harness({ database });
    const endpoint = `${application.origin}/api/v2/brain/attack-knowledge/bundles/${compiled.bundleFingerprint}/evidence`;
    expect((await fetch(endpoint)).status).toBe(401);
    application.setActor({ id: "reviewer-router", type: "reviewer" });
    expect((await fetch(endpoint)).status).toBe(403);
    application.setActor({ id: "operator-router", type: "operator" });
    application.setAuthorize(false);
    expect((await fetch(endpoint)).status).toBe(403);
    application.setAuthorize(true);
    application.setAuthorizeEvidence(false);
    const hidden = await fetch(endpoint);
    expect(hidden.status).toBe(404);
    expect(await hidden.json()).toMatchObject({ error: { code: "promotion_bundle_not_found" } });
  });

  test("keeps historical unbound bundles visible but blocked and rejects arbitrary evidence IDs", async () => {
    const { database, compiled, evidenceIds } = fixture(false);
    const application = await harness({ database, actor: { id: "operator-router", type: "operator" } });
    const root = `${application.origin}/api/v2/brain/attack-knowledge/bundles/${compiled.bundleFingerprint}`;
    const page = await (await fetch(`${application.origin}/api/v2/brain/attack-knowledge/bundles?status=staged`)).json() as any;
    expect(page.items[0]).toMatchObject({ boundEvidenceCount: 0, status: "staged" });
    expect((await (await fetch(`${root}/evidence`)).json())).toMatchObject({ items: [], totalReturned: 0 });

    const blocked = await fetch(`${root}/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationEvidenceIds: [] }),
    });
    expect(blocked.status).toBe(200);
    expect(await blocked.json()).toMatchObject({
      ready: false,
      blockers: [expect.objectContaining({ code: "verification_evidence_missing" })],
    });
    const arbitrary = await fetch(`${root}/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationEvidenceIds: [evidenceIds[0]] }),
    });
    expect(arbitrary.status).toBe(400);
    expect(await arbitrary.json()).toMatchObject({ error: { code: "promotion_evidence_not_bound" } });
  });

  test("promotes one exact reviewed hash idempotently and leaves an immutable receipt", async () => {
    const { database, compiled, evidenceIds } = fixture();
    const application = await harness({ database, actor: { id: "operator-router", type: "operator" } });
    const root = `${application.origin}/api/v2/brain/attack-knowledge/bundles/${compiled.bundleFingerprint}`;
    const preview = await (await fetch(`${root}/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verificationEvidenceIds: evidenceIds }),
    })).json() as any;
    expect(preview).toMatchObject({ ready: true, replay: false, blockers: [] });
    expect(preview.reviewHash).toMatch(/^[a-f0-9]{64}$/u);
    const request = () => fetch(`${root}/promote`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "promotion-router-decision-001" },
      body: JSON.stringify({ expectedReviewHash: preview.reviewHash, verificationEvidenceIds: evidenceIds }),
    });
    const first = await request();
    expect(first.status).toBe(200);
    const receipt = await first.json() as any;
    expect(receipt).toMatchObject({ status: "materialized", reviewHash: preview.reviewHash });
    const replay = await request();
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(receipt);
    expect(database.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_promotion_receipts").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE action = 'attack_knowledge.promoted'").get()).toEqual({ count: 1 });

    const reused = await fetch(`${root}/promote`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "promotion-router-decision-001" },
      body: JSON.stringify({ expectedReviewHash: preview.reviewHash, verificationEvidenceIds: [evidenceIds[0]] }),
    });
    expect(reused.status).toBe(409);
    expect(await reused.json()).toMatchObject({ error: { code: "idempotency_key_reused" } });

    const reusableState = JSON.stringify({
      nodes: database.prepare("SELECT title, summary, body FROM memory_nodes").all(),
      edges: database.prepare("SELECT title, summary, explanation FROM memory_edges").all(),
      profiles: database.prepare("SELECT * FROM operational_hazard_profiles").all(),
    });
    expect(reusableState).not.toContain("ReaperTwo");
    expect(reusableState).not.toContain("10.129.39.191");
    expect(reusableState).not.toContain("/root/private");
  });

  test("is exported and mounted after standalone authentication and CSRF enforcement", () => {
    const migrationIndex = readFileSync(new URL("../index.ts", import.meta.url), "utf8");
    const serverSource = readFileSync(new URL("../../index.ts", import.meta.url), "utf8");
    expect(migrationIndex).toContain('export * from "./AttackKnowledgePromotionRouter"');
    const authentication = serverSource.indexOf('web.use("/api/v2", (request, response, next) =>');
    const router = serverSource.indexOf("web.use(createAttackKnowledgePromotionRouter");
    expect(authentication).toBeGreaterThan(-1);
    expect(router).toBeGreaterThan(authentication);
  });
});
