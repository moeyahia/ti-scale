import type { SqliteDatabase } from "../db";
import { parseJsonObject } from "./serialization";
import {
  RunIntelligenceError,
  type IntelligenceProvenance,
  type OsiDerivation,
  type OsiLayerNumber,
  type TopologyEdge,
  type TopologyEvidenceLink,
  type TopologyNode,
} from "./types";

interface NodeRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly node_type: string;
  readonly primary_label: string;
  readonly normalized_identity: string;
  readonly scope_status: TopologyNode["scopeStatus"];
  readonly lifecycle_state: TopologyNode["lifecycleState"];
  readonly properties_json: string;
  readonly confidence: number;
  readonly verification_state: TopologyNode["verificationState"];
  readonly originating_agent_id: string | null;
  readonly originating_tool: string | null;
  readonly sensitivity: TopologyNode["sensitivity"];
  readonly first_seen_at: string;
  readonly last_seen_at: string;
}

interface EdgeRow {
  readonly id: string;
  readonly mission_id: string;
  readonly source_node_id: string;
  readonly target_node_id: string;
  readonly edge_type: string;
  readonly properties_json: string;
  readonly confidence: number;
  readonly verification_state: TopologyEdge["verificationState"];
  readonly sensitivity: TopologyEdge["sensitivity"];
  readonly first_seen_at: string;
  readonly last_seen_at: string;
}

interface EvidenceRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly verification_state: TopologyEvidenceLink["verificationState"];
  readonly confidence: number;
  readonly content_hash: string;
  readonly summary: string;
  readonly provenance_json: string;
}

interface EvidenceLinkRow extends EvidenceRow {
  readonly relationship: TopologyEvidenceLink["relationship"];
  readonly created_at: string;
}

interface OsiRow {
  readonly id: string;
  readonly asset_node_id: string;
  readonly osi_layer: OsiLayerNumber;
  readonly category: string;
  readonly value: string;
  readonly version_value: string | null;
  readonly derivation: OsiDerivation;
  readonly confidence: number;
  readonly evidence_id: string;
  readonly observed_at: string;
  readonly conflict_group_id: string | null;
  readonly evidence_verification_state: TopologyEvidenceLink["verificationState"];
  readonly evidence_provenance_json: string;
}

interface StoredTopologyProperties {
  readonly data: ReturnType<typeof parseJsonObject>;
  readonly provenance: IntelligenceProvenance;
}

function provenanceFrom(value: unknown, fallbackAgent: string | null, fallbackTool: string | null): IntelligenceProvenance {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new RunIntelligenceError("topology_provenance_corrupt", "Stored topology provenance is invalid");
  }
  const source = value as Record<string, unknown>;
  const method = typeof source.method === "string" ? source.method : "";
  const sourceRef = typeof source.sourceRef === "string" ? source.sourceRef : "";
  const sourceAgentId = typeof source.sourceAgentId === "string" ? source.sourceAgentId : fallbackAgent ?? undefined;
  const sourceTool = typeof source.sourceTool === "string" ? source.sourceTool : fallbackTool ?? undefined;
  const observationIds = Array.isArray(source.observationIds)
    && source.observationIds.every((item) => typeof item === "string")
    ? source.observationIds
    : undefined;
  if (!method || !sourceRef || (!sourceAgentId && !sourceTool)) {
    throw new RunIntelligenceError("topology_provenance_corrupt", "Stored topology provenance is incomplete");
  }
  return {
    method,
    sourceRef,
    ...(sourceAgentId ? { sourceAgentId } : {}),
    ...(sourceTool ? { sourceTool } : {}),
    ...(observationIds ? { observationIds } : {}),
  };
}

function storedProperties(value: string, fallbackAgent: string | null, fallbackTool: string | null): StoredTopologyProperties {
  const parsed = parseJsonObject(value, "Topology properties");
  const data = parsed.data;
  const provenance = parsed.provenance;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new RunIntelligenceError("topology_properties_corrupt", "Stored topology data is not an object");
  }
  return {
    data: data as ReturnType<typeof parseJsonObject>,
    provenance: provenanceFrom(provenance, fallbackAgent, fallbackTool),
  };
}

function mapEvidence(row: EvidenceLinkRow): TopologyEvidenceLink {
  return {
    evidenceId: row.id,
    relationship: row.relationship,
    verificationState: row.verification_state,
    confidence: row.confidence,
    contentHash: row.content_hash,
    summary: row.summary,
    provenance: parseJsonObject(row.provenance_json, `Evidence ${row.id} provenance`),
    createdAt: row.created_at,
  };
}

export class ReconDigitalTwinRepository {
  constructor(private readonly database: SqliteDatabase) {}

  getEvidence(evidenceId: string): EvidenceRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, verification_state, confidence,
        content_hash, summary, provenance_json
      FROM evidence WHERE id = ?
    `).get(evidenceId) as EvidenceRow | undefined;
    if (!row) throw new RunIntelligenceError("evidence_not_found", `Evidence not found: ${evidenceId}`);
    return row;
  }

  getNodeRow(nodeId: string): NodeRow {
    const row = this.database.prepare("SELECT * FROM topology_nodes WHERE id = ?").get(nodeId) as NodeRow | undefined;
    if (!row) throw new RunIntelligenceError("topology_node_not_found", `Topology node not found: ${nodeId}`);
    return row;
  }

  getNode(nodeId: string): TopologyNode {
    const row = this.getNodeRow(nodeId);
    const stored = storedProperties(row.properties_json, row.originating_agent_id, row.originating_tool);
    return {
      id: row.id,
      missionId: row.mission_id,
      runId: row.run_id,
      nodeType: row.node_type,
      primaryLabel: row.primary_label,
      normalizedIdentity: row.normalized_identity,
      scopeStatus: row.scope_status,
      lifecycleState: row.lifecycle_state,
      properties: stored.data,
      provenance: stored.provenance,
      confidence: row.confidence,
      verificationState: row.verification_state,
      sensitivity: row.sensitivity,
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
      evidence: this.evidenceLinks("node", row.id),
    };
  }

  getEdge(edgeId: string): TopologyEdge {
    const row = this.database.prepare("SELECT * FROM topology_edges WHERE id = ?").get(edgeId) as EdgeRow | undefined;
    if (!row) throw new RunIntelligenceError("topology_edge_not_found", `Topology edge not found: ${edgeId}`);
    const stored = storedProperties(row.properties_json, null, null);
    return {
      id: row.id,
      missionId: row.mission_id,
      sourceNodeId: row.source_node_id,
      targetNodeId: row.target_node_id,
      edgeType: row.edge_type,
      properties: stored.data,
      provenance: stored.provenance,
      confidence: row.confidence,
      verificationState: row.verification_state,
      sensitivity: row.sensitivity,
      firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at,
      evidence: this.evidenceLinks("edge", row.id),
    };
  }

  listNodes(missionId: string, runId?: string): TopologyNode[] {
    const rows = (runId === undefined
      ? this.database.prepare(`
          SELECT id FROM topology_nodes WHERE mission_id = ?
          ORDER BY node_type, normalized_identity, id
        `).all(missionId)
      : this.database.prepare(`
          SELECT id FROM topology_nodes
          WHERE mission_id = ? AND (run_id = ? OR run_id IS NULL)
          ORDER BY node_type, normalized_identity, id
        `).all(missionId, runId)) as Array<{ readonly id: string }>;
    return rows.map(({ id }) => this.getNode(id));
  }

  listEdges(missionId: string, includedNodeIds?: ReadonlySet<string>): TopologyEdge[] {
    const rows = this.database.prepare(`
      SELECT id, source_node_id, target_node_id FROM topology_edges
      WHERE mission_id = ? ORDER BY edge_type, source_node_id, target_node_id, id
    `).all(missionId) as Array<{
      readonly id: string;
      readonly source_node_id: string;
      readonly target_node_id: string;
    }>;
    return rows
      .filter((row) => !includedNodeIds || (includedNodeIds.has(row.source_node_id) && includedNodeIds.has(row.target_node_id)))
      .map(({ id }) => this.getEdge(id));
  }

  evidenceLinks(subjectType: "node" | "edge", subjectId: string): TopologyEvidenceLink[] {
    const rows = this.database.prepare(`
      SELECT e.id, e.mission_id, e.run_id, e.verification_state, e.confidence,
        e.content_hash, e.summary, e.provenance_json, tel.relationship, tel.created_at
      FROM topology_evidence_links tel
      JOIN evidence e ON e.id = tel.evidence_id
      WHERE tel.subject_type = ? AND tel.subject_id = ?
      ORDER BY tel.created_at,
        CASE tel.relationship WHEN 'supports' THEN 0 WHEN 'source' THEN 1 ELSE 2 END,
        e.id, tel.relationship
    `).all(subjectType, subjectId) as EvidenceLinkRow[];
    return rows.map(mapEvidence);
  }

  insertNode(input: {
    readonly id: string;
    readonly missionId: string;
    readonly runId: string | null;
    readonly nodeType: string;
    readonly primaryLabel: string;
    readonly normalizedIdentity: string;
    readonly scopeStatus: TopologyNode["scopeStatus"];
    readonly lifecycleState: TopologyNode["lifecycleState"];
    readonly propertiesJson: string;
    readonly confidence: number;
    readonly verificationState: TopologyNode["verificationState"];
    readonly originatingAgentId: string | null;
    readonly originatingTool: string | null;
    readonly sensitivity: TopologyNode["sensitivity"];
    readonly firstSeenAt: string;
    readonly lastSeenAt: string;
    readonly createdAt: string;
  }): TopologyNode {
    this.database.prepare(`
      INSERT INTO topology_nodes (
        id, mission_id, run_id, node_type, primary_label, normalized_identity,
        scope_status, lifecycle_state, properties_json, confidence,
        verification_state, originating_agent_id, originating_tool, sensitivity,
        first_seen_at, last_seen_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.id,
      input.missionId,
      input.runId,
      input.nodeType,
      input.primaryLabel,
      input.normalizedIdentity,
      input.scopeStatus,
      input.lifecycleState,
      input.propertiesJson,
      input.confidence,
      input.verificationState,
      input.originatingAgentId,
      input.originatingTool,
      input.sensitivity,
      input.firstSeenAt,
      input.lastSeenAt,
      input.createdAt,
      input.createdAt,
    );
    return this.getNode(input.id);
  }

  insertEdge(input: {
    readonly id: string;
    readonly missionId: string;
    readonly sourceNodeId: string;
    readonly targetNodeId: string;
    readonly edgeType: string;
    readonly propertiesJson: string;
    readonly confidence: number;
    readonly verificationState: TopologyEdge["verificationState"];
    readonly sensitivity: TopologyEdge["sensitivity"];
    readonly firstSeenAt: string;
    readonly lastSeenAt: string;
  }): TopologyEdge {
    this.database.prepare(`
      INSERT INTO topology_edges (
        id, mission_id, source_node_id, target_node_id, edge_type,
        properties_json, confidence, verification_state, sensitivity,
        first_seen_at, last_seen_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.id,
      input.missionId,
      input.sourceNodeId,
      input.targetNodeId,
      input.edgeType,
      input.propertiesJson,
      input.confidence,
      input.verificationState,
      input.sensitivity,
      input.firstSeenAt,
      input.lastSeenAt,
    );
    return this.getEdge(input.id);
  }

  insertEvidenceLink(input: {
    readonly subjectType: "node" | "edge";
    readonly subjectId: string;
    readonly evidenceId: string;
    readonly relationship: TopologyEvidenceLink["relationship"];
    readonly createdAt: string;
  }): void {
    this.database.prepare(`
      INSERT INTO topology_evidence_links (
        subject_type, subject_id, evidence_id, relationship, created_at
      ) VALUES (?, ?, ?, ?, ?)
    `).run(input.subjectType, input.subjectId, input.evidenceId, input.relationship, input.createdAt);
  }

  insertOsiObservation(input: {
    readonly id: string;
    readonly assetNodeId: string;
    readonly layer: OsiLayerNumber;
    readonly category: string;
    readonly value: string;
    readonly versionValue: string | null;
    readonly derivation: OsiDerivation;
    readonly confidence: number;
    readonly evidenceId: string;
    readonly observedAt: string;
    readonly conflictGroupId: string | null;
  }): void {
    this.database.prepare(`
      INSERT INTO asset_layer_observations (
        id, asset_node_id, osi_layer, category, value, version_value,
        derivation, confidence, evidence_id, observed_at, conflict_group_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      input.id,
      input.assetNodeId,
      input.layer,
      input.category,
      input.value,
      input.versionValue,
      input.derivation,
      input.confidence,
      input.evidenceId,
      input.observedAt,
      input.conflictGroupId,
    );
  }

  listOsiObservations(assetNodeId: string): OsiRow[] {
    return this.database.prepare(`
      SELECT alo.id, alo.asset_node_id, alo.osi_layer, alo.category,
        alo.value, alo.version_value, alo.derivation, alo.confidence,
        alo.evidence_id, alo.observed_at, alo.conflict_group_id,
        e.verification_state AS evidence_verification_state,
        e.provenance_json AS evidence_provenance_json
      FROM asset_layer_observations alo
      JOIN evidence e ON e.id = alo.evidence_id
      WHERE alo.asset_node_id = ?
      ORDER BY alo.osi_layer, alo.category, alo.observed_at, alo.id
    `).all(assetNodeId) as OsiRow[];
  }
}
