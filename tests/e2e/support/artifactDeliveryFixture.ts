import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory";
import { ObsidianVaultBridge, VaultPathPolicy } from "../../../server/vault";
import { E2E_DATABASE_PATH, E2E_VAULT_ROOT } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const NOW = "2026-07-16T20:00:00.000Z";
const LATER = "2026-07-16T20:01:00.000Z";

function sha256(body: Uint8Array | string): string {
  return createHash("sha256").update(body).digest("hex");
}

export interface ArtifactDeliveryFixture {
  readonly missionId: string;
  readonly runId: string;
  readonly readyArtifactId: string;
  readonly reconciliationArtifactId: string;
  readonly quarantinedArtifactId: string;
  readonly hashMismatchArtifactId: string;
  readonly crossScopeArtifactId: string;
  readonly readyEvidenceId: string;
  readonly content: Buffer;
  readonly contentHash: string;
  readonly vaultConnectionId: string;
}

export interface ArtifactDownloadAudit {
  readonly resourceId: string;
  readonly actorId: string | null;
  readonly details: Record<string, unknown>;
  readonly reason: string | null;
  readonly recordHash: string;
}

/**
 * Seeds only namespaced records and files into the disposable E2E stores.
 * Existing fixtures and operator data are never replaced or deleted.
 */
export function createArtifactDeliveryFixture(instanceId: string): ArtifactDeliveryFixture {
  if (!E2E_DATABASE_PATH) throw new Error("Artifact-delivery E2E requires the isolated V2 database path");
  const namespace = normalizeFixtureNamespace(instanceId);
  const fixtureId = (prefix: string): string => `${prefix}-${namespace}`;
  const missionId = fixtureId("mission-delivery");
  const runId = fixtureId("run-delivery");
  const otherMissionId = fixtureId("mission-delivery-other");
  const otherRunId = fixtureId("run-delivery-other");
  const readyArtifactId = fixtureId("artifact-delivery-ready");
  const reconciliationArtifactId = fixtureId("artifact-delivery-reconcile");
  const quarantinedArtifactId = fixtureId("artifact-delivery-quarantine");
  const hashMismatchArtifactId = fixtureId("artifact-delivery-mismatch");
  const crossScopeArtifactId = fixtureId("artifact-delivery-cross-scope");
  const readyEvidenceId = fixtureId("evidence-delivery-ready");
  const vaultConnectionId = fixtureId("vault-delivery");
  const vaultRelativePath = fixtureId("artifact-delivery-vault");
  const content = Buffer.from(
    `Ti-Scale Ti-Scale verified artifact delivery fixture\nnamespace=${namespace}\n`,
    "utf8",
  );
  const contentHash = sha256(content);
  const expectedMismatchBody = Buffer.from("expected-integrity-body-000000", "utf8");
  const tamperedMismatchBody = Buffer.from("tampered-integrity-body-000000", "utf8");
  if (expectedMismatchBody.length !== tamperedMismatchBody.length) {
    throw new Error("Artifact-delivery mismatch fixture must preserve byte size while changing content");
  }
  const mismatchHash = sha256(expectedMismatchBody);

  const database = createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const vaultPolicy = new VaultPathPolicy(E2E_VAULT_ROOT);
    const vault = new ObsidianVaultBridge(
      database,
      new MemoryRepository(database),
      vaultPolicy,
      { clock: () => new Date(NOW) },
    );
    const connection = vault.connect({
      id: vaultConnectionId,
      vaultPath: vaultRelativePath,
      displayName: `Artifact delivery fixture ${namespace}`,
      permissionGranted: true,
      syncScope: { fixture: "artifact_delivery", namespace },
    });
    vaultPolicy.atomicWriteBytes(
      connection.vaultPath,
      `.ti-scale/attachments/${contentHash}`,
      content,
    );
    // Deliberately name the changed bytes after the expected digest. Metadata
    // remains structurally valid, so only the final descriptor-open hash check
    // can detect the integrity failure.
    vaultPolicy.atomicWriteBytes(
      connection.vaultPath,
      `.ti-scale/attachments/${mismatchHash}`,
      tamperedMismatchBody,
    );

    inImmediateTransaction(database, () => {
      const insertMission = database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          engagement_id, scope_json, success_criteria_json,
          retention_policy_json, memory_policy_json, created_by,
          created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, '[]', '{}', '{}',
          'e2e-local-operator', ?, ?, 'ti_scale')
      `);
      insertMission.run(
        missionId,
        "Verified artifact delivery fixture",
        "Prove bounded content delivery and fail-closed reconciliation",
        fixtureId("engagement-delivery"),
        JSON.stringify({ environment: "authorized_local_fixture", targets: ["local-vault-fixture"] }),
        NOW,
        LATER,
      );
      insertMission.run(
        otherMissionId,
        "Cross-scope artifact fixture",
        "Prove evidence from another engagement cannot authorize content delivery",
        fixtureId("engagement-delivery-other"),
        JSON.stringify({ environment: "authorized_local_fixture", targets: ["other-local-vault-fixture"] }),
        NOW,
        LATER,
      );

      const insertRun = database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          next_action_summary, budget_json, budget_usage_json,
          created_at, updated_at, version, control_plane
        ) VALUES (?, ?, 'guided', 'completed', 1, ?, 'Review retained artifact integrity',
          '{}', '{}', ?, ?, 1, 'ti_scale')
      `);
      insertRun.run(runId, missionId, "Canonical fixture completed without target execution", NOW, LATER);
      insertRun.run(otherRunId, otherMissionId, "Independent cross-scope fixture completed", NOW, LATER);

      const insertArtifact = database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
        ) VALUES (?, ?, ?, 'guided', 'obsidian_attachment', ?, ?, ?,
          'text/plain', 'internal', ?, ?)
      `);
      const canonicalStorage = `vault-attachment://${encodeURIComponent(vaultConnectionId)}/${contentHash}`;
      insertArtifact.run(readyArtifactId, missionId, runId, canonicalStorage, contentHash, content.length, "{}", LATER);
      insertArtifact.run(reconciliationArtifactId, missionId, runId, canonicalStorage, contentHash, content.length, "{}", LATER);
      insertArtifact.run(
        quarantinedArtifactId,
        missionId,
        runId,
        canonicalStorage,
        contentHash,
        content.length,
        JSON.stringify({ lifecycleState: "quarantined", quarantineReason: "fixture_policy_boundary" }),
        LATER,
      );
      insertArtifact.run(
        hashMismatchArtifactId,
        missionId,
        runId,
        `vault-attachment://${encodeURIComponent(vaultConnectionId)}/${mismatchHash}`,
        mismatchHash,
        tamperedMismatchBody.length,
        "{}",
        LATER,
      );
      insertArtifact.run(crossScopeArtifactId, missionId, runId, canonicalStorage, contentHash, content.length, "{}", LATER);

      const insertEvidence = database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, 'e2e-artifact-delivery', ?, 'local-vault-fixture',
          'file_artifact_with_hash', ?, ?, 1, 'internal', 'verified', ?, ?,
          'e2e-local-operator', ?)
      `);
      insertEvidence.run(
        readyEvidenceId,
        missionId,
        runId,
        LATER,
        contentHash,
        JSON.stringify({ method: "local_content_addressed_fixture", sourceRefs: [vaultConnectionId] }),
        "Verified content-addressed local fixture attachment",
        readyArtifactId,
        LATER,
      );
      insertEvidence.run(
        fixtureId("evidence-delivery-quarantine"),
        missionId,
        runId,
        LATER,
        contentHash,
        JSON.stringify({ method: "local_quarantine_fixture", sourceRefs: [vaultConnectionId] }),
        "Verified provenance retained before quarantine",
        quarantinedArtifactId,
        LATER,
      );
      insertEvidence.run(
        fixtureId("evidence-delivery-mismatch"),
        missionId,
        runId,
        LATER,
        mismatchHash,
        JSON.stringify({ method: "canonical_metadata_fixture", sourceRefs: [vaultConnectionId] }),
        "Canonical metadata awaiting final byte-integrity verification",
        hashMismatchArtifactId,
        LATER,
      );
      // The foreign key proves that this is a real relationship, while the
      // different mission/run proves that it cannot satisfy the delivery gate.
      insertEvidence.run(
        fixtureId("evidence-delivery-cross-scope"),
        otherMissionId,
        otherRunId,
        LATER,
        contentHash,
        JSON.stringify({ method: "cross_engagement_fixture", sourceRefs: [vaultConnectionId] }),
        "Verified evidence from a different engagement",
        crossScopeArtifactId,
        LATER,
      );
    });

    return {
      missionId,
      runId,
      readyArtifactId,
      reconciliationArtifactId,
      quarantinedArtifactId,
      hashMismatchArtifactId,
      crossScopeArtifactId,
      readyEvidenceId,
      content,
      contentHash,
      vaultConnectionId,
    };
  } finally {
    database.close();
  }
}

export function readArtifactDownloadAudits(artifactIds: readonly string[]): readonly ArtifactDownloadAudit[] {
  if (!E2E_DATABASE_PATH) throw new Error("Artifact-delivery E2E requires the isolated V2 database path");
  const selected = new Set(artifactIds);
  const database = createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    readonly: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const rows = database.prepare(`
      SELECT resource_id, actor_id, details_json, reason, record_hash
      FROM audit_records
      WHERE action = 'artifact.content_downloaded'
      ORDER BY occurred_at, id
    `).all() as Array<{
      resource_id: string;
      actor_id: string | null;
      details_json: string;
      reason: string | null;
      record_hash: string;
    }>;
    return rows
      .filter((row) => selected.has(row.resource_id))
      .map((row) => ({
        resourceId: row.resource_id,
        actorId: row.actor_id,
        details: JSON.parse(row.details_json) as Record<string, unknown>,
        reason: row.reason,
        recordHash: row.record_hash,
      }));
  } finally {
    database.close();
  }
}
