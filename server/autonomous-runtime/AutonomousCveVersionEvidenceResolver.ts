import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import type { VerifiedServiceProductVersionEvidence } from "../cve-intelligence";

export const AUTONOMOUS_CVE_VERSION_EVIDENCE_RESOLVER_VERSION =
  "ti-scale.autonomous-cve-version-evidence-resolver.v1" as const;

interface VersionEvidenceRow {
  readonly evidence_id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly acquired_at: string;
  readonly content_hash: string;
  readonly provenance_json: string;
  readonly extracted_text: string;
  readonly evidence_confidence: number;
  readonly asset_node_id: string;
  readonly service_node_id: string;
  readonly service_properties_json: string;
  readonly service_confidence: number;
  readonly originating_agent_id: string | null;
  readonly log_record_id: string;
  readonly log_content_hash: string;
}

function record(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : undefined;
}

function topologyData(value: unknown): Readonly<Record<string, unknown>> | undefined {
  const properties = record(value);
  if (!properties) return undefined;
  return record(properties.data) ?? properties;
}

function bounded(value: unknown, maximum = 500): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.normalize("NFC").trim().replace(/\s+/gu, " ");
  return normalized && normalized.length <= maximum
    && !/[\u0000-\u001F\u007F]/u.test(normalized) ? normalized : undefined;
}

/**
 * Nmap's structured result still labels a detected version as a banner. This
 * parser only separates an explicit product prefix and version token; it does
 * not infer a vendor, CPE, affected range, or CVE.
 */
export function parseBannerProductVersion(input: Readonly<{
  service: string;
  version: string;
}>): Readonly<{ readonly product: string; readonly version: string }> | undefined {
  const service = bounded(input.service, 80);
  const banner = bounded(input.version, 300);
  if (!service || !banner) return undefined;
  const match = /^(.*?)(?:\s+|^)(v?\d+(?:\.\d+)+(?:[A-Za-z][A-Za-z0-9.-]*)?)(?:\s|$)/u.exec(banner);
  if (!match) return undefined;
  const product = bounded(match[1], 200) ?? service;
  const version = match[2]?.replace(/^v/u, "");
  if (!product || !version || version.length > 200) return undefined;
  return Object.freeze({ product, version });
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Resolves only verified evidence-backed topology. Raw stdout, an unlinked
 * banner, an unverified node, or a service without an explicit version token
 * is not eligible for Autonomous CVE candidate generation.
 */
export class AutonomousCveVersionEvidenceResolver {
  constructor(private readonly database: SqliteDatabase) {}

  resolve(input: Readonly<{
    missionId: string;
    runId: string;
    stepId: string;
    target: string;
    fallbackAgentId: string;
  }>): readonly VerifiedServiceProductVersionEvidence[] {
    const rows = this.database.prepare(`
      SELECT e.id AS evidence_id, e.mission_id, e.run_id, e.step_id,
        e.acquired_at, e.content_hash, e.provenance_json, e.extracted_text,
        e.confidence AS evidence_confidence,
        asset.id AS asset_node_id, service.id AS service_node_id,
        service.properties_json AS service_properties_json,
        service.confidence AS service_confidence,
        service.originating_agent_id,
        log.id AS log_record_id, log.content_hash AS log_content_hash
      FROM evidence e
      JOIN topology_evidence_links service_link
        ON service_link.evidence_id = e.id
        AND service_link.subject_type = 'node'
        AND service_link.relationship = 'supports'
      JOIN topology_nodes service
        ON service.id = service_link.subject_id
        AND service.node_type = 'service'
        AND service.mission_id = e.mission_id
        AND service.run_id = e.run_id
        AND service.scope_status = 'allowed'
        AND service.verification_state = 'verified'
      JOIN topology_edges edge
        ON edge.target_node_id = service.id
        AND edge.edge_type = 'exposes'
        AND edge.mission_id = e.mission_id
        AND edge.verification_state = 'verified'
      JOIN topology_nodes asset
        ON asset.id = edge.source_node_id
        AND asset.node_type = 'asset'
        AND asset.mission_id = e.mission_id
        AND asset.run_id = e.run_id
        AND asset.scope_status = 'allowed'
        AND asset.verification_state = 'verified'
      JOIN observation_log_sources source
        ON source.observation_id = json_extract(e.extracted_text, '$.observationId')
      JOIN engagement_log_records log
        ON log.id = source.log_record_id
        AND log.mission_id = e.mission_id
        AND log.run_id = e.run_id
      WHERE e.mission_id = ? AND e.run_id = ?
        AND e.evidence_type = 'service_version_fingerprint'
        AND e.verification_state = 'verified'
        AND COALESCE(
          json_extract(asset.properties_json, '$.data.address'),
          json_extract(asset.properties_json, '$.address')
        ) = ?
      ORDER BY e.acquired_at, e.id, service.id
    `).all(input.missionId, input.runId, input.target) as VersionEvidenceRow[];

    return Object.freeze(rows.flatMap((row) => {
      let properties: Readonly<Record<string, unknown>> | undefined;
      try { properties = topologyData(JSON.parse(row.service_properties_json) as unknown); } catch { return []; }
      const service = bounded(properties?.service, 80);
      const rawVersion = bounded(properties?.version, 300);
      const parsed = service && rawVersion
        ? parseBannerProductVersion({ service, version: rawVersion })
        : undefined;
      if (!parsed) return [];
      const receiptSha256 = sha256(row.provenance_json);
      return [Object.freeze({
        schemaVersion: "ti-scale.verified-service-version-evidence.v1" as const,
        evidenceId: row.evidence_id,
        missionId: row.mission_id,
        runId: row.run_id,
        // Candidate generation is a later step, but the immutable evidence
        // retains the originating evidence step for correct provenance.
        stepId: row.step_id,
        assetNodeId: row.asset_node_id,
        serviceNodeId: row.service_node_id,
        evidenceType: "service_version_fingerprint" as const,
        verificationState: "verified" as const,
        product: Object.freeze({ product: parsed.product }),
        detectedVersion: parsed.version,
        versionPrecision: "exact" as const,
        method: "tool_banner_parser" as const,
        confidence: Number(Math.min(row.evidence_confidence, row.service_confidence, 0.88).toFixed(4)),
        sourceRefs: Object.freeze([Object.freeze({
          kind: "engagement_log" as const,
          id: row.log_record_id,
          contentSha256: row.log_content_hash,
        })]),
        acquiredAt: row.acquired_at,
        createdByAgentId: row.originating_agent_id ?? input.fallbackAgentId,
        verificationReceiptId: `verification:${row.evidence_id}`,
        verificationReceiptSha256: receiptSha256,
        evidenceContentSha256: row.content_hash,
      })];
    }));
  }
}
