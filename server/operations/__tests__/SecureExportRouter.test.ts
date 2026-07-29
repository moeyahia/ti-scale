import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { createOperationsRouter } from "../../routes/operationsRoutes";
import { VaultPathPolicy } from "../../vault";
import type { OperationsAccessPolicy } from "../types";

const NOW = "2026-07-15T18:00:00.000Z";
const LATER = "2026-07-15T18:01:00.000Z";
const servers: Server[] = [];
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function hash(body: string | Uint8Array): string {
  return createHash("sha256").update(body).digest("hex");
}

function seed(
  database: ReturnType<typeof createDatabaseConnection>,
  policy: VaultPathPolicy,
): void {
  const mission = database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Authorized export test', 'guided', ?, 'operator-test', ?, ?)
  `);
  mission.run("mission-a", "Authorized mission", "eng-a", NOW, LATER);
  mission.run("mission-b", "Outside-scope mission", "eng-b", NOW, LATER);
  mission.run("mission-legacy", "Imported legacy mission", "eng-a", NOW, LATER);
  const run = database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, progress, created_at, updated_at)
    VALUES (?, ?, 'guided', 'completed', 1, ?, ?)
  `);
  run.run("run-a", "mission-a", NOW, LATER);
  run.run("run-b", "mission-b", NOW, LATER);
  run.run("run-legacy", "mission-legacy", NOW, LATER);
  database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = 'mission-legacy'").run();
  database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = 'run-legacy'").run();

  const vaultPath = policy.resolveVault("brain-a");
  mkdirSync(policy.resolveRelative(vaultPath, ".ti-scale/attachments", true), { recursive: true });
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, created_at, updated_at
    ) VALUES ('vault-a', ?, 'Authorized vault', 'connected', '{}', ?, ?, ?)
  `).run(vaultPath, NOW, NOW, LATER);

  const goodBody = Buffer.from("verified attachment bytes", "utf8");
  const goodHash = hash(goodBody);
  policy.atomicWriteBytes(vaultPath, `.ti-scale/attachments/${goodHash}`, goodBody);
  const artifact = database.prepare(`
    INSERT INTO artifacts (
      id, mission_id, run_id, journey, artifact_type, storage_uri, content_hash,
      byte_size, media_type, sensitivity, metadata_json, created_at
    ) VALUES (?, ?, ?, 'guided', ?, ?, ?, ?, 'text/plain', ?, '{}', ?)
  `);
  artifact.run(
    "artifact-good",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );
  artifact.run(
    "artifact-restricted",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "restricted",
    LATER,
  );
  artifact.run(
    "artifact-cross-scope",
    "mission-b",
    "run-b",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );
  artifact.run(
    "artifact-file-uri",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    "file:///root/.ssh/id_ed25519",
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );
  database.prepare(`
    UPDATE artifacts SET metadata_json = ? WHERE id = 'artifact-file-uri'
  `).run(JSON.stringify({
    sourcePath: "/root/.ssh/id_ed25519",
    fileUri: "file:///root/.ssh/id_ed25519",
    windowsPath: "C:\\Users\\operator\\secrets.txt",
    traversalPath: "../../outside/private.txt",
    safe: "retained semantic metadata",
  }));
  artifact.run(
    "artifact-traversal-uri",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/../../${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );

  const expectedHash = hash("expected");
  policy.atomicWriteBytes(
    vaultPath,
    `.ti-scale/attachments/${expectedHash}`,
    Buffer.from("tampered", "utf8"),
  );
  artifact.run(
    "artifact-hash-mismatch",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${expectedHash}`,
    expectedHash,
    8,
    "internal",
    LATER,
  );

  const sizeBody = Buffer.from("size", "utf8");
  const sizeHash = hash(sizeBody);
  policy.atomicWriteBytes(vaultPath, `.ti-scale/attachments/${sizeHash}`, sizeBody);
  artifact.run(
    "artifact-size-mismatch",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${sizeHash}`,
    sizeHash,
    sizeBody.length + 1,
    "internal",
    LATER,
  );

  const symlinkBody = "symlink content";
  const symlinkHash = hash(symlinkBody);
  const outside = join(temporaryDirectories.at(-1)!, "outside-attachment");
  writeFileSync(outside, symlinkBody, { mode: 0o600 });
  symlinkSync(outside, policy.resolveRelative(vaultPath, `.ti-scale/attachments/${symlinkHash}`));
  artifact.run(
    "artifact-symlink",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${symlinkHash}`,
    symlinkHash,
    Buffer.byteLength(symlinkBody),
    "internal",
    LATER,
  );
  artifact.run(
    "artifact-unlinked",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );
  artifact.run(
    "artifact-unverified",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );
  artifact.run(
    "artifact-raw-output",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );
  artifact.run(
    "artifact-quarantined",
    "mission-a",
    "run-a",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );
  database.prepare(`
    UPDATE artifacts SET metadata_json = '{"lifecycleState":"quarantined"}'
    WHERE id = 'artifact-quarantined'
  `).run();
  artifact.run(
    "artifact-legacy",
    "mission-legacy",
    "run-legacy",
    "obsidian_attachment",
    `vault-attachment://vault-a/${goodHash}`,
    goodHash,
    goodBody.length,
    "internal",
    LATER,
  );

  const evidence = database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, artifact_id,
      created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'verification', ?, ?, 0.9, ?, 'verified', ?, ?, ?, 'agent-test', ?)
  `);
  evidence.run(
    "evidence-a-public", "mission-a", "run-a", "fixture:public", NOW,
    "public.test", hash("public"), "{}", "public", "Public evidence", null, null, NOW,
  );
  evidence.run(
    "evidence-a-internal", "mission-a", "run-a", "file:///private/source.json", LATER,
    "internal.test", hash("internal"), "{}", "internal", "Internal evidence", null, "artifact-good", LATER,
  );
  evidence.run(
    "evidence-a-private", "mission-a", "run-a", "fixture:private", LATER,
    "private.test", hash("private"), '{"authorization":"Bearer provenance-secret-value"}', "private",
    "password=summary-secret-value", "password=raw-secret-value", null, LATER,
  ); // gitleaks:allow -- synthetic redaction fixture
  evidence.run(
    "evidence-a-restricted", "mission-a", "run-a", "fixture:restricted", LATER,
    "restricted.test", hash("restricted"), "{}", "restricted", "Restricted evidence", null, "artifact-restricted", LATER,
  );
  evidence.run(
    "evidence-b", "mission-b", "run-b", "fixture:hidden", LATER,
    "hidden.test", hash("hidden"), "{}", "public", "Outside-scope evidence", null, null, LATER,
  );
  for (const artifactId of [
    "artifact-traversal-uri",
    "artifact-hash-mismatch",
    "artifact-size-mismatch",
    "artifact-symlink",
    "artifact-quarantined",
  ]) {
    evidence.run(
      `evidence-${artifactId}`, "mission-a", "run-a", "fixture:artifact", LATER,
      "artifact.test", hash(`evidence-${artifactId}`), "{}", "internal",
      `Verified evidence for ${artifactId}`, null, artifactId, LATER,
    );
  }
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, artifact_id,
      created_by, created_at
    ) VALUES (
      'evidence-artifact-unverified', 'mission-a', 'run-a', 'fixture:artifact', ?,
      'artifact.test', 'verification', ?, '{}', 0.9, 'internal', 'unverified',
      'Unverified evidence for artifact', NULL, 'artifact-unverified', 'agent-test', ?
    )
  `).run(LATER, hash("evidence-artifact-unverified"), LATER);
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, artifact_id,
      created_by, created_at
    ) VALUES (
      'evidence-artifact-raw-output', 'mission-a', 'run-a', 'mcp:scanner.run', ?,
      'artifact.test', 'command_output', ?, '{"processSucceeded":true}', 0.95,
      'internal', 'verified', 'Successful process output is not evidence', NULL,
      'artifact-raw-output', 'runtime', ?
    )
  `).run(LATER, hash("evidence-artifact-raw-output"), LATER);
  evidence.run(
    "evidence-artifact-legacy", "mission-legacy", "run-legacy", "fixture:artifact", LATER,
    "artifact.test", hash("evidence-artifact-legacy"), "{}", "internal",
    "Verified imported evidence", null, "artifact-legacy", LATER,
  );

  const chain = database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES (?, ?, 'acquired', 'agent-test', ?, ?)
  `);
  chain.run("chain-public", "evidence-a-public", '{"token":"chain-secret-one"}', NOW); // gitleaks:allow -- synthetic fixture
  chain.run("chain-internal", "evidence-a-internal", '{"token":"chain-secret-two"}', LATER); // gitleaks:allow -- synthetic fixture
  chain.run("chain-private", "evidence-a-private", '{"token":"chain-secret-three"}', LATER); // gitleaks:allow -- synthetic fixture

  database.prepare(`
    INSERT INTO findings (
      id, mission_id, run_id, title, severity, confidence, affected_scope,
      description, impact, review_status, created_at, updated_at
    ) VALUES (
      'finding-a', 'mission-a', 'run-a', 'Evidence-backed finding', 'low', 0.9,
      'authorized.test', 'Bounded finding', 'Bounded impact', 'verified', ?, ?
    )
  `).run(NOW, LATER);
  database.prepare(`
    INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
    VALUES ('finding-a', 'evidence-a-public', 'supports', ?)
  `).run(LATER);

  const audit = database.prepare(`
    INSERT INTO audit_records (
      id, mission_id, run_id, journey, actor_type, actor_id, action,
      resource_type, resource_id, reason, details_json, previous_hash,
      record_hash, occurred_at
    ) VALUES (?, ?, ?, 'guided', 'operator', 'operator-test', ?, 'run', ?, ?, ?, ?, ?, ?)
  `);
  const firstHash = "1".repeat(64);
  const secondHash = "2".repeat(64);
  audit.run(
    "audit-a-1", "mission-a", "run-a", "run.started", "run-a",
    "Authorized start from /private/vault/source.json",
    '{"authorization":"Bearer audit-secret-one","vaultPath":"/private/vault/source.json"}',
    null, firstHash, NOW,
  ); // gitleaks:allow -- synthetic redaction fixture
  audit.run(
    "audit-a-2", "mission-a", "run-a", "evidence.recorded", "run-a",
    "password=audit-secret-two", '{"safe":true}', firstHash, secondHash, LATER,
  ); // gitleaks:allow -- synthetic redaction fixture
  audit.run(
    "audit-a-3", "mission-a", "run-a", "run.completed", "run-a",
    "Completed", '{}', secondHash, "3".repeat(64), LATER,
  );
  audit.run(
    "audit-b-1", "mission-b", "run-b", "run.started", "run-b",
    "Outside-scope audit", '{}', "3".repeat(64), "4".repeat(64), LATER,
  );
}

async function application() {
  const directory = mkdtempSync(join(tmpdir(), "secure-export-test-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "ti-scale.sqlite") });
  migrateDatabase(database);
  const policy = new VaultPathPolicy(join(directory, "allowed-vaults"));
  seed(database, policy);
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createOperationsRouter({
    database,
    vaultPathPolicy: policy,
    maximumArtifactDownloadBytes: 1_024,
    maximumSecureExportBytes: 128 * 1_024,
    maximumSecureExportRecords: 2,
    clock: () => new Date("2026-07-15T18:02:00.000Z"),
    resolveActor: () => ({ id: "reviewer-test", type: "reviewer" }),
    resolveAccess: (request): OperationsAccessPolicy => ({
      maximumSensitivity: request.get("X-Test-Sensitivity") === "restricted" ? "restricted" : "private",
      ...(request.get("X-Test-Scope") === "all"
        ? { allEngagements: true }
        : { engagementIds: ["eng-a"], missionIds: ["mission-a"] }),
      canDownloadArtifactContent: request.get("X-Test-Deny-Exports") !== "1",
      canExportEvidenceBundles: request.get("X-Test-Deny-Exports") !== "1",
      canExportAuditRecords: request.get("X-Test-Deny-Exports") !== "1",
    }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  };
}

describe("canonical secure artifact and export delivery", () => {
  test("delivers only verified vault attachments with inert server-derived headers and an immutable audit", async () => {
    const { database, url } = await application();
    try {
      const metadataResponse = await fetch(`${url}/api/v2/intelligence/artifacts/artifact-good`);
      expect(metadataResponse.status).toBe(200);
      expect(await metadataResponse.json()).toMatchObject({
        id: "artifact-good",
        storage: { scheme: "vault-attachment" },
        delivery: {
          state: "ready",
          downloadable: true,
          code: "artifact_delivery_ready",
          verifiedEvidenceCount: 1,
        },
        evidence: [{ id: "evidence-a-internal", verificationState: "verified" }],
      });
      const response = await fetch(`${url}/api/v2/intelligence/artifacts/artifact-good/download`);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/octet-stream");
      expect(response.headers.get("content-disposition")).toBe(
        'attachment; filename="ti-scale-artifact-artifact-good.bin"',
      );
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(response.headers.get("cross-origin-resource-policy")).toBe("same-origin");
      expect(response.headers.get("content-security-policy")).toBe("sandbox");
      expect(response.headers.get("cache-control")).toBe("no-store");
      const downloaded = Buffer.from(await response.arrayBuffer());
      expect(response.headers.get("content-length")).toBe(String(downloaded.length));
      expect(downloaded.toString("utf8")).toBe("verified attachment bytes");
      const audit = database.prepare(`
        SELECT action, actor_id, details_json, reason, record_hash
        FROM audit_records WHERE resource_id = 'artifact-good'
          AND action = 'artifact.content_downloaded'
      `).get() as Record<string, string>;
      expect(audit).toMatchObject({
        action: "artifact.content_downloaded",
        actor_id: "reviewer-test",
      });
      expect(audit.details_json).toContain(hash("verified attachment bytes"));
      expect(audit.record_hash).toMatch(/^[a-f0-9]{64}$/u);
      expect(JSON.stringify(audit)).not.toContain("allowed-vaults");
      expect(JSON.stringify(audit)).not.toContain("vault-a/");
    } finally {
      database.close();
    }
  });

  test("projects and enforces precise reconciliation states before touching artifact storage", async () => {
    const { database, url } = await application();
    try {
      const cases = [
        {
          id: "artifact-unlinked",
          state: "reconciliation_required",
          code: "artifact_verified_evidence_required",
          category: "reconciliation_required",
        },
        {
          id: "artifact-unverified",
          state: "reconciliation_required",
          code: "artifact_verified_evidence_required",
          category: "reconciliation_required",
        },
        {
          id: "artifact-raw-output",
          state: "reconciliation_required",
          code: "artifact_verified_evidence_required",
          category: "reconciliation_required",
        },
        {
          id: "artifact-quarantined",
          state: "quarantined",
          code: "artifact_content_quarantined",
          category: "artifact_quarantined",
        },
        {
          id: "artifact-legacy",
          state: "reconciliation_required",
          code: "artifact_control_plane_reconciliation_required",
          category: "reconciliation_required",
        },
      ] as const;
      for (const item of cases) {
        const metadata = await fetch(`${url}/api/v2/intelligence/artifacts/${item.id}`);
        expect(metadata.status).toBe(200);
        const metadataBody = await metadata.json() as any;
        expect(metadataBody.delivery).toMatchObject({
          state: item.state,
          downloadable: false,
          code: item.code,
        });
        expect(JSON.stringify(metadataBody.delivery)).not.toContain("allowed-vaults");

        const response = await fetch(`${url}/api/v2/intelligence/artifacts/${item.id}/download`);
        expect(response.status).toBe(409);
        const body = await response.json() as any;
        expect(body.error).toMatchObject({
          code: item.code,
          retryable: false,
          category: item.category,
          details: { deliveryState: item.state },
        });
        expect(body.error.humanMessage).toEqual(expect.any(String));
        expect(body.error.remediation).toEqual(expect.any(String));
        expect(body.error.traceId).toEqual(expect.any(String));
        expect(JSON.stringify(body)).not.toContain("allowed-vaults");
      }
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE resource_id IN (
          'artifact-unlinked', 'artifact-unverified', 'artifact-raw-output',
          'artifact-quarantined', 'artifact-legacy'
        ) AND action = 'artifact.content_downloaded'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("fails closed across mission scope, sensitivity, explicit permission, and unsupported schemes", async () => {
    const { database, url } = await application();
    try {
      expect((await fetch(`${url}/api/v2/intelligence/artifacts/artifact-cross-scope/download`)).status).toBe(404);
      expect((await fetch(`${url}/api/v2/intelligence/artifacts/artifact-restricted/download`)).status).toBe(404);
      expect((await fetch(`${url}/api/v2/intelligence/artifacts/artifact-good/download`, {
        headers: { "X-Test-Deny-Exports": "1" },
      })).status).toBe(403);
      const restricted = await fetch(`${url}/api/v2/intelligence/artifacts/artifact-restricted/download`, {
        headers: { "X-Test-Sensitivity": "restricted" },
      });
      expect(restricted.status).toBe(200);
      const unsupported = await fetch(`${url}/api/v2/intelligence/artifacts/artifact-file-uri/download`);
      expect(unsupported.status).toBe(409);
      const unsupportedBody = JSON.stringify(await unsupported.json());
      expect(unsupportedBody).not.toContain("/root/.ssh");
      expect(unsupportedBody).not.toContain("file://");
      const unsupportedMetadata = await fetch(`${url}/api/v2/intelligence/artifacts/artifact-file-uri`);
      expect(unsupportedMetadata.status).toBe(200);
      const projectedMetadata = JSON.stringify(await unsupportedMetadata.json());
      expect(projectedMetadata).toContain("retained semantic metadata");
      expect(projectedMetadata).not.toContain("/root/.ssh");
      expect(projectedMetadata).not.toContain("file://");
      expect(projectedMetadata).not.toContain("C:\\\\Users");
      expect(projectedMetadata).not.toContain("../../outside");
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE resource_id = 'artifact-file-uri' AND action = 'artifact.content_downloaded'
      `).get()).toEqual({ count: 0 });

      const missing = await fetch(`${url}/api/v2/intelligence/artifacts/missing-artifact/download`, {
        headers: { "X-Request-ID": "missing-artifact-reconciliation" },
      });
      expect(missing.status).toBe(404);
      expect(await missing.json()).toMatchObject({ error: {
        code: "artifact_content_not_found",
        category: "not_found",
        traceId: "missing-artifact-reconciliation",
      } });
    } finally {
      database.close();
    }
  });

  test("rejects traversal, symbolic links, size mismatch, and hash mismatch without a success audit", async () => {
    const { database, url } = await application();
    try {
      for (const id of [
        "artifact-traversal-uri",
        "artifact-symlink",
        "artifact-size-mismatch",
        "artifact-hash-mismatch",
      ]) {
        const response = await fetch(`${url}/api/v2/intelligence/artifacts/${id}/download`);
        expect(response.status).toBe(409);
        const serialized = JSON.stringify(await response.json());
        expect(serialized).not.toContain("allowed-vaults");
        expect(serialized).not.toContain("vault-a");
      }
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE resource_id IN (
          'artifact-traversal-uri', 'artifact-symlink',
          'artifact-size-mismatch', 'artifact-hash-mismatch'
        ) AND action = 'artifact.content_downloaded'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("fails closed without recreating a missing configured vault during download", async () => {
    const { database, url } = await application();
    try {
      const connection = database.prepare(`
        SELECT vault_path FROM vault_connections WHERE id = 'vault-a'
      `).get() as { vault_path: string };
      rmSync(connection.vault_path, { recursive: true, force: true });
      expect(existsSync(connection.vault_path)).toBe(false);
      const response = await fetch(`${url}/api/v2/intelligence/artifacts/artifact-good/download`);
      expect(response.status).toBe(409);
      expect(existsSync(connection.vault_path)).toBe(false);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE resource_id = 'artifact-good' AND action = 'artifact.content_downloaded'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("exports a bounded redacted evidence metadata bundle and audits the export", async () => {
    const { database, url } = await application();
    try {
      const response = await fetch(`${url}/api/v2/intelligence/evidence/runs/run-a/export`);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-disposition")).toBe(
        'attachment; filename="ti-scale-run-a-evidence.json"',
      );
      expect(response.headers.get("content-security-policy")).toBe("sandbox");
      const exported = await response.json() as any;
      expect(exported).toMatchObject({
        schemaVersion: "2.4",
        exportKind: "run_evidence_metadata",
        mission: { id: "mission-a" },
        run: { id: "run-a", journey: "guided" },
        truncation: { evidence: true },
        privacy: { metadataOnly: true },
        integrity: { algorithm: "sha256" },
      });
      expect(exported.evidence).toHaveLength(2);
      expect(exported.evidence.map((item: any) => item.id)).toEqual([
        "evidence-a-public",
        "evidence-a-internal",
      ]);
      expect(exported.artifacts).toMatchObject([{
        id: "artifact-good",
        storageScheme: "vault-attachment",
      }]);
      expect(exported.evidence[1].source).toBe("[REDACTED LOCATION]");
      const serialized = JSON.stringify(exported);
      for (const forbiddenValue of [
        "raw-secret-value",
        "provenance-secret-value",
        "chain-secret-one",
        "/private/",
        "allowed-vaults",
        "vault-a/",
        "Outside-scope evidence",
        "evidence-b",
        "Restricted evidence",
      ]) expect(serialized).not.toContain(forbiddenValue);
      expect(exported.evidence[0]).not.toHaveProperty("extractedText");
      expect(exported.evidence[0]).not.toHaveProperty("provenance");
      expect(exported.chainOfCustody[0]).not.toHaveProperty("details");
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE run_id = 'run-a' AND action = 'evidence.bundle_exported'
      `).get()).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT record_hash FROM audit_records
        WHERE run_id = 'run-a' AND action = 'evidence.bundle_exported'
      `).get()).toMatchObject({ record_hash: expect.stringMatching(/^[a-f0-9]{64}$/u) });
      expect((await fetch(`${url}/api/v2/intelligence/evidence/runs/run-b/export`)).status).toBe(404);
    } finally {
      database.close();
    }
  });

  test("requires restricted access and exports only a bounded redacted run-scoped audit subset", async () => {
    const { database, url } = await application();
    try {
      expect((await fetch(`${url}/api/v2/observability/audit/runs/run-a/export`)).status).toBe(403);
      const response = await fetch(`${url}/api/v2/observability/audit/runs/run-a/export`, {
        headers: { "X-Test-Sensitivity": "restricted" },
      });
      expect(response.status).toBe(200);
      expect(response.headers.get("content-disposition")).toBe(
        'attachment; filename="ti-scale-run-a-audit.json"',
      );
      const exported = await response.json() as any;
      expect(exported).toMatchObject({
        schemaVersion: "2.4",
        exportKind: "run_audit_records",
        mission: { id: "mission-a" },
        run: { id: "run-a" },
        selection: { scope: "exact_run", globalChainSubset: true },
        truncation: { records: true },
        privacy: { redacted: true },
      });
      expect(exported.records.map((item: any) => item.id)).toEqual(["audit-a-1", "audit-a-2"]);
      const serialized = JSON.stringify(exported);
      expect(serialized).toContain("[REDACTED]");
      for (const forbiddenValue of [
        "audit-secret-one",
        "audit-secret-two",
        "/private/vault",
        "Outside-scope audit",
        "audit-b-1",
      ]) expect(serialized).not.toContain(forbiddenValue);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE run_id = 'run-a' AND action = 'audit.records_exported'
      `).get()).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT record_hash FROM audit_records
        WHERE run_id = 'run-a' AND action = 'audit.records_exported'
      `).get()).toMatchObject({ record_hash: expect.stringMatching(/^[a-f0-9]{64}$/u) });
      expect((await fetch(`${url}/api/v2/observability/audit/runs/run-b/export`, {
        headers: { "X-Test-Sensitivity": "restricted" },
      })).status).toBe(404);
    } finally {
      database.close();
    }
  });
});
