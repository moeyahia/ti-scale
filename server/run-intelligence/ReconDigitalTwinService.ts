import { randomUUID } from "node:crypto";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import { canonicalJson, canonicalObject, type JsonObject } from "./serialization";
import { ReconDigitalTwinRepository } from "./ReconDigitalTwinRepository";
import {
  OSI_LAYERS,
  RunIntelligenceError,
  type AssetOsiStack,
  type CreateTopologyEdgeInput,
  type CreateTopologyNodeInput,
  type IntelligenceProvenance,
  type OsiLayerNumber,
  type OsiLayerObservation,
  type ReconDigitalTwin,
  type RecordOsiObservationInput,
  type TopologyEvidenceRelationship,
  type TopologyVerificationState,
} from "./types";

const LAYER_NAMES: Readonly<Record<OsiLayerNumber, string>> = {
  1: "Physical",
  2: "Data Link",
  3: "Network",
  4: "Transport",
  5: "Session",
  6: "Presentation",
  7: "Application",
};

const ASSET_NODE_TYPES = new Set(["asset", "host", "network_device", "cloud_asset", "container", "cluster"]);

function text(value: string, label: string, maximum = 1_000): string {
  const normalized = value.normalize("NFKC").trim();
  if (!normalized) throw new RunIntelligenceError("invalid_topology_input", `${label} is required`);
  if (normalized.length > maximum) throw new RunIntelligenceError("invalid_topology_input", `${label} is too long`);
  return normalized;
}

function timestamp(value: string, label: string): string {
  if (!Number.isFinite(Date.parse(value))) throw new RunIntelligenceError("invalid_timestamp", `${label} must be an ISO timestamp`);
  return value;
}

function confidence(value: number): number {
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new RunIntelligenceError("invalid_confidence", "Topology confidence must be between zero and one");
  }
  return value;
}

function provenance(value: IntelligenceProvenance): IntelligenceProvenance {
  const method = text(value.method, "Provenance method");
  const sourceRef = text(value.sourceRef, "Provenance source reference");
  const sourceAgentId = value.sourceAgentId ? text(value.sourceAgentId, "Source agent ID") : undefined;
  const sourceTool = value.sourceTool ? text(value.sourceTool, "Source tool") : undefined;
  if (!sourceAgentId && !sourceTool) {
    throw new RunIntelligenceError("topology_origin_required", "Topology provenance requires an originating agent or tool");
  }
  return {
    method,
    sourceRef,
    ...(sourceAgentId ? { sourceAgentId } : {}),
    ...(sourceTool ? { sourceTool } : {}),
    ...(value.observationIds ? { observationIds: value.observationIds.map((id) => text(id, "Observation ID")) } : {}),
  };
}

function uniqueEvidence(
  links: readonly { readonly evidenceId: string; readonly relationship: TopologyEvidenceRelationship }[],
): void {
  if (links.length === 0) {
    throw new RunIntelligenceError("topology_evidence_required", "Every topology node and edge requires canonical evidence");
  }
  const seen = new Set<string>();
  for (const link of links) {
    const evidenceId = text(link.evidenceId, "Evidence ID");
    const key = `${evidenceId}\0${link.relationship}`;
    if (seen.has(key)) throw new RunIntelligenceError("duplicate_evidence_link", "Duplicate topology evidence relationship");
    seen.add(key);
  }
}

export class ReconDigitalTwinService {
  readonly repository: ReconDigitalTwinRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.repository = new ReconDigitalTwinRepository(database);
  }

  #validateMissionRun(missionId: string, runId: string | undefined): void {
    const mission = this.database.prepare("SELECT id FROM missions WHERE id = ?").get(missionId);
    if (!mission) throw new RunIntelligenceError("mission_not_found", `Mission not found: ${missionId}`);
    if (runId) {
      const run = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(runId) as
        | { readonly mission_id: string }
        | undefined;
      if (!run || run.mission_id !== missionId) {
        throw new RunIntelligenceError("run_mission_mismatch", "Topology run does not belong to the supplied mission");
      }
    }
  }

  #validateOrigin(value: IntelligenceProvenance): IntelligenceProvenance {
    const normalized = provenance(value);
    if (normalized.sourceAgentId) {
      const agent = this.database.prepare("SELECT id FROM agents WHERE id = ?").get(normalized.sourceAgentId);
      if (!agent) throw new RunIntelligenceError("originating_agent_not_found", "Topology originating agent is unknown");
    }
    return normalized;
  }

  #validateEvidence(input: {
    readonly missionId: string;
    readonly runId?: string;
    readonly verificationState: TopologyVerificationState;
    readonly links: readonly { readonly evidenceId: string; readonly relationship: TopologyEvidenceRelationship }[];
  }): void {
    uniqueEvidence(input.links);
    let verified = 0;
    let supporting = 0;
    let contradicting = 0;
    for (const link of input.links) {
      const evidence = this.repository.getEvidence(link.evidenceId);
      if (evidence.mission_id !== input.missionId || (evidence.run_id !== null && input.runId !== undefined && evidence.run_id !== input.runId)) {
        throw new RunIntelligenceError("topology_evidence_scope_mismatch", "Topology evidence is outside the node or edge scope");
      }
      if (evidence.verification_state === "rejected") {
        throw new RunIntelligenceError("topology_evidence_rejected", "Rejected evidence cannot support topology intelligence");
      }
      if (Object.keys(parseEvidenceProvenance(evidence.provenance_json, evidence.id)).length === 0) {
        throw new RunIntelligenceError("topology_evidence_provenance_missing", "Topology evidence requires canonical provenance");
      }
      if (evidence.verification_state === "verified") verified += 1;
      if (link.relationship === "supports" || link.relationship === "source") supporting += 1;
      if (link.relationship === "contradicts") contradicting += 1;
    }
    if (input.verificationState === "verified" && verified === 0) {
      throw new RunIntelligenceError("verified_topology_requires_verified_evidence", "Verified topology requires verified evidence");
    }
    if (input.verificationState === "corroborated" && input.links.length < 2) {
      throw new RunIntelligenceError("corroboration_requires_multiple_sources", "Corroborated topology requires multiple evidence links");
    }
    if (input.verificationState === "conflicting" && (supporting === 0 || contradicting === 0)) {
      throw new RunIntelligenceError("conflict_evidence_required", "Conflicting topology must preserve supporting and contradicting evidence");
    }
  }

  createNode(input: CreateTopologyNodeInput): ReturnType<ReconDigitalTwinRepository["getNode"]> {
    const normalizedProvenance = this.#validateOrigin(input.provenance);
    const firstSeenAt = timestamp(input.firstSeenAt, "First-seen time");
    const lastSeenAt = timestamp(input.lastSeenAt, "Last-seen time");
    if (Date.parse(lastSeenAt) < Date.parse(firstSeenAt)) {
      throw new RunIntelligenceError("invalid_observation_window", "Topology last-seen time precedes first-seen time");
    }
    const now = this.clock().toISOString();
    return inImmediateTransaction(this.database, () => {
      this.#validateMissionRun(input.missionId, input.runId);
      this.#validateEvidence({
        missionId: input.missionId,
        ...(input.runId ? { runId: input.runId } : {}),
        verificationState: input.verificationState,
        links: input.evidence,
      });
      const id = `topology_node_${randomUUID()}`;
      this.repository.insertNode({
        id,
        missionId: input.missionId,
        runId: input.runId ?? null,
        nodeType: text(input.nodeType, "Node type"),
        primaryLabel: text(input.primaryLabel, "Primary label"),
        normalizedIdentity: text(input.normalizedIdentity, "Normalized identity").toLocaleLowerCase("en-US"),
        scopeStatus: input.scopeStatus,
        lifecycleState: input.lifecycleState,
        propertiesJson: canonicalJson({ data: canonicalObject(input.properties ?? {}), provenance: normalizedProvenance }),
        confidence: confidence(input.confidence),
        verificationState: input.verificationState,
        originatingAgentId: normalizedProvenance.sourceAgentId ?? null,
        originatingTool: normalizedProvenance.sourceTool ?? null,
        sensitivity: input.sensitivity,
        firstSeenAt,
        lastSeenAt,
        createdAt: now,
      });
      for (const link of input.evidence) {
        this.repository.insertEvidenceLink({
          subjectType: "node",
          subjectId: id,
          evidenceId: link.evidenceId,
          relationship: link.relationship,
          createdAt: now,
        });
      }
      return this.repository.getNode(id);
    });
  }

  createEdge(input: CreateTopologyEdgeInput): ReturnType<ReconDigitalTwinRepository["getEdge"]> {
    if (input.sourceNodeId === input.targetNodeId) {
      throw new RunIntelligenceError("self_topology_edge", "A topology edge cannot point to itself");
    }
    const normalizedProvenance = this.#validateOrigin(input.provenance);
    const firstSeenAt = timestamp(input.firstSeenAt, "First-seen time");
    const lastSeenAt = timestamp(input.lastSeenAt, "Last-seen time");
    if (Date.parse(lastSeenAt) < Date.parse(firstSeenAt)) {
      throw new RunIntelligenceError("invalid_observation_window", "Topology last-seen time precedes first-seen time");
    }
    return inImmediateTransaction(this.database, () => {
      this.#validateMissionRun(input.missionId, undefined);
      const source = this.repository.getNodeRow(input.sourceNodeId);
      const target = this.repository.getNodeRow(input.targetNodeId);
      if (source.mission_id !== input.missionId || target.mission_id !== input.missionId) {
        throw new RunIntelligenceError("topology_edge_scope_mismatch", "Topology edge endpoints must belong to its mission");
      }
      if (source.run_id !== null && target.run_id !== null && source.run_id !== target.run_id) {
        throw new RunIntelligenceError("topology_edge_run_mismatch", "Topology edge endpoints cannot cross run boundaries");
      }
      const edgeRunId = source.run_id ?? target.run_id ?? undefined;
      this.#validateEvidence({
        missionId: input.missionId,
        ...(edgeRunId ? { runId: edgeRunId } : {}),
        verificationState: input.verificationState,
        links: input.evidence,
      });
      const id = `topology_edge_${randomUUID()}`;
      const now = this.clock().toISOString();
      this.repository.insertEdge({
        id,
        missionId: input.missionId,
        sourceNodeId: input.sourceNodeId,
        targetNodeId: input.targetNodeId,
        edgeType: text(input.edgeType, "Edge type"),
        propertiesJson: canonicalJson({ data: canonicalObject(input.properties ?? {}), provenance: normalizedProvenance }),
        confidence: confidence(input.confidence),
        verificationState: input.verificationState,
        sensitivity: input.sensitivity,
        firstSeenAt,
        lastSeenAt,
      });
      for (const link of input.evidence) {
        this.repository.insertEvidenceLink({
          subjectType: "edge",
          subjectId: id,
          evidenceId: link.evidenceId,
          relationship: link.relationship,
          createdAt: now,
        });
      }
      return this.repository.getEdge(id);
    });
  }

  getGraph(missionId: string, runId?: string): ReconDigitalTwin {
    this.#validateMissionRun(missionId, runId);
    const nodes = this.repository.listNodes(missionId, runId);
    const nodeIds = new Set(nodes.map(({ id }) => id));
    return {
      missionId,
      runId: runId ?? null,
      nodes,
      edges: this.repository.listEdges(missionId, nodeIds),
    };
  }

  recordOsiObservation(input: RecordOsiObservationInput): OsiLayerObservation {
    const observedAt = timestamp(input.observedAt, "OSI observation time");
    return inImmediateTransaction(this.database, () => {
      const asset = this.repository.getNodeRow(input.assetNodeId);
      if (!ASSET_NODE_TYPES.has(asset.node_type)) {
        throw new RunIntelligenceError("osi_asset_required", "OSI observations may be attached only to an asset node");
      }
      const evidence = this.repository.getEvidence(input.evidenceId);
      if (evidence.mission_id !== asset.mission_id || (evidence.run_id !== null && asset.run_id !== null && evidence.run_id !== asset.run_id)) {
        throw new RunIntelligenceError("osi_evidence_scope_mismatch", "OSI evidence is outside the asset scope");
      }
      if (evidence.verification_state === "rejected") {
        throw new RunIntelligenceError("osi_evidence_rejected", "Rejected evidence cannot support an OSI observation");
      }
      if (Object.keys(parseEvidenceProvenance(evidence.provenance_json, evidence.id)).length === 0) {
        throw new RunIntelligenceError("osi_evidence_provenance_missing", "OSI evidence requires canonical provenance");
      }
      if (input.derivation === "actively_verified" && evidence.verification_state !== "verified") {
        throw new RunIntelligenceError("osi_verification_mismatch", "An actively verified OSI value requires verified evidence");
      }
      const id = `osi_observation_${randomUUID()}`;
      this.repository.insertOsiObservation({
        id,
        assetNodeId: asset.id,
        layer: input.layer,
        category: text(input.category, "OSI category"),
        value: text(input.value, "OSI value", 4_000),
        versionValue: input.versionValue ? text(input.versionValue, "Version value") : null,
        derivation: input.derivation,
        confidence: confidence(input.confidence),
        evidenceId: input.evidenceId,
        observedAt,
        conflictGroupId: input.conflictGroupId ? text(input.conflictGroupId, "Conflict group") : null,
      });
      return this.getOsiStack(asset.id).layers[input.layer - 1]!.observations.find((item) => item.id === id)!;
    });
  }

  getOsiStack(assetNodeId: string): AssetOsiStack {
    const asset = this.repository.getNodeRow(assetNodeId);
    if (!ASSET_NODE_TYPES.has(asset.node_type)) {
      throw new RunIntelligenceError("osi_asset_required", "OSI stack is available only for asset nodes");
    }
    const rows = this.repository.listOsiObservations(assetNodeId);
    return {
      assetNodeId,
      layers: OSI_LAYERS.map((layer) => {
        const layerRows = rows.filter((row) => row.osi_layer === layer);
        const observations: OsiLayerObservation[] = layerRows.map((row) => ({
          id: row.id,
          assetNodeId: row.asset_node_id,
          layer: row.osi_layer,
          category: row.category,
          value: row.value,
          versionValue: row.version_value,
          derivation: row.derivation,
          confidence: row.confidence,
          evidenceId: row.evidence_id,
          evidenceVerificationState: row.evidence_verification_state,
          evidenceProvenance: parseEvidenceProvenance(row.evidence_provenance_json, row.evidence_id),
          observedAt: row.observed_at,
          conflictGroupId: row.conflict_group_id,
        }));
        const conflicts = new Map<string, Set<string>>();
        for (const observation of observations) {
          if (!observation.conflictGroupId) continue;
          const values = conflicts.get(observation.conflictGroupId) ?? new Set<string>();
          values.add(`${observation.category}\0${observation.value}\0${observation.versionValue ?? ""}`);
          conflicts.set(observation.conflictGroupId, values);
        }
        const isConflicting = observations.some(({ evidenceVerificationState }) => evidenceVerificationState === "disputed")
          || [...conflicts.values()].some((values) => values.size > 1);
        return {
          layer,
          name: LAYER_NAMES[layer],
          state: observations.length === 0 ? "not_observed" : isConflicting ? "conflicting" : "observed",
          observations,
        };
      }),
    };
  }
}

function parseEvidenceProvenance(value: string, evidenceId: string): JsonObject {
  try {
    return canonicalObject(JSON.parse(value) as unknown);
  } catch {
    throw new RunIntelligenceError("evidence_provenance_invalid", `Evidence ${evidenceId} has invalid provenance`);
  }
}
