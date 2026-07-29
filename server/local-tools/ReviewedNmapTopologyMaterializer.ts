import type { SqliteDatabase } from "../db";
import type { Observation } from "../intelligence-v24";
import { ReconDigitalTwinService } from "../run-intelligence/ReconDigitalTwinService";
import { runScopedTopologyIdentity } from "../run-intelligence/RunScopedTopologyIdentity";
import type { TopologyNode } from "../run-intelligence/types";

const NMAP_TOOL_ID = "kali:nmap-tcp-connect-service-scan" as const;
const FULL_TCP_BASELINE_TOOL_ID = "ti-scale:autonomous-full-tcp-baseline" as const;
const NMAP_OBSERVATION_TYPE = "tcp_service_scan" as const;

interface AllowedTargetRow {
  readonly id: string;
}

interface ParsedOpenPort {
  readonly port: number;
  readonly transport: "tcp";
  readonly state: "open";
  readonly service: string;
  readonly version: string | null;
}

export interface ReviewedNmapTopologyMaterialization {
  readonly status: "materialized" | "skipped";
  readonly reason:
    | "reviewed_nmap_observation"
    | "not_reviewed_nmap"
    | "not_run_scoped"
    | "scan_not_complete"
    | "target_not_allowed"
    | "normalized_result_invalid";
  readonly assetNodeId?: string;
  readonly serviceNodeIds: readonly string[];
  readonly edgeIds: readonly string[];
}

function record(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : undefined;
}

function boundedText(value: unknown, maximum: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.normalize("NFKC").trim();
  return normalized && normalized.length <= maximum ? normalized : undefined;
}

function openPort(value: unknown): ParsedOpenPort | undefined {
  const candidate = record(value);
  if (!candidate) return undefined;
  const port = candidate.port;
  const service = candidate.service === null
    ? "unknown"
    : boundedText(candidate.service, 80);
  if (
    !Number.isSafeInteger(port)
    || (port as number) < 1
    || (port as number) > 65_535
    || candidate.transport !== "tcp"
    || candidate.state !== "open"
    || !service
  ) return undefined;
  const version = candidate.version === null
    ? null
    : boundedText(candidate.version, 300) ?? null;
  return {
    port: port as number,
    transport: "tcp",
    state: "open",
    service,
    version,
  };
}

/**
 * Projects only a structured, attributable Nmap observation into run-scoped
 * topology. The bounded legacy route remains unverified. The Full-TCP route
 * may supply already-verified canonical evidence IDs, in which case every
 * projected node/edge is linked to that evidence and marked verified. Raw
 * stdout/stderr remains exclusively in the Engagement Log. This materializer
 * never creates evidence, CVE candidates, findings, or unobserved OS facts.
 */
export class ReviewedNmapTopologyMaterializer {
  readonly #topology: ReconDigitalTwinService;

  constructor(private readonly database: SqliteDatabase) {
    this.#topology = new ReconDigitalTwinService(database);
  }

  materialize(
    observation: Observation,
    options: Readonly<{ readonly verifiedEvidenceIds?: readonly string[] }> = {},
  ): ReviewedNmapTopologyMaterialization {
    if (
      observation.observationType !== NMAP_OBSERVATION_TYPE
      || (observation.sourceTool !== NMAP_TOOL_ID
        && observation.sourceTool !== FULL_TCP_BASELINE_TOOL_ID)
    ) {
      return { status: "skipped", reason: "not_reviewed_nmap", serviceNodeIds: [], edgeIds: [] };
    }
    if (!observation.runId) {
      return { status: "skipped", reason: "not_run_scoped", serviceNodeIds: [], edgeIds: [] };
    }
    const normalized = record(observation.normalizedValue);
    const result = record(normalized?.result);
    const host = boundedText(result?.host, 1_000);
    if (
      !normalized
      || normalized.missionId !== observation.missionId
      || normalized.runId !== observation.runId
      || normalized.toolId !== observation.sourceTool
      || !result
      || !host
      || !Array.isArray(result.openPorts)
    ) {
      return { status: "skipped", reason: "normalized_result_invalid", serviceNodeIds: [], edgeIds: [] };
    }
    if (result.scanCompleted !== true) {
      return { status: "skipped", reason: "scan_not_complete", serviceNodeIds: [], edgeIds: [] };
    }
    const targetId = boundedText(normalized.missionTargetId, 240);
    const allowedTarget = (targetId
      ? this.database.prepare(`
          SELECT id FROM mission_targets
          WHERE id = ? AND mission_id = ? AND disposition = 'allowed'
            AND (target = ? COLLATE NOCASE OR normalized_target = ? COLLATE NOCASE)
          LIMIT 1
        `).get(targetId, observation.missionId, host, host)
      : this.database.prepare(`
          SELECT id FROM mission_targets
          WHERE mission_id = ? AND disposition = 'allowed'
            AND (target = ? COLLATE NOCASE OR normalized_target = ? COLLATE NOCASE)
          ORDER BY created_at, id LIMIT 1
        `).get(observation.missionId, host, host)) as AllowedTargetRow | undefined;
    if (!allowedTarget) {
      return { status: "skipped", reason: "target_not_allowed", serviceNodeIds: [], edgeIds: [] };
    }

    const evidenceIds = [...(options.verifiedEvidenceIds ?? [])];
    if (evidenceIds.length > 10_000
      || new Set(evidenceIds).size !== evidenceIds.length
      || evidenceIds.some((value) => !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$/u.test(value))) {
      return { status: "skipped", reason: "normalized_result_invalid", serviceNodeIds: [], edgeIds: [] };
    }
    const verificationState = evidenceIds.length > 0 ? "verified" as const : "unverified" as const;
    const evidence = Object.freeze(evidenceIds.map((evidenceId) => Object.freeze({
      evidenceId,
      relationship: "supports" as const,
    })));

    const openPorts = result.openPorts
      .map(openPort)
      .filter((candidate): candidate is ParsedOpenPort => candidate !== undefined)
      .filter((candidate, index, records) => records.findIndex(
        (other) => other.port === candidate.port && other.transport === candidate.transport,
      ) === index);
    const provenance = {
      method: "reviewed_local_nmap_observation",
      sourceRef: observation.id,
      ...(observation.sourceAgentId ? { sourceAgentId: observation.sourceAgentId } : {}),
      sourceTool: observation.sourceTool,
      observationIds: [observation.id],
    } as const;
    const assetIdentity = runScopedTopologyIdentity(observation.runId, "asset", host);
    const asset = this.#topology.repository.findNodeByIdentity({
      missionId: observation.missionId,
      runId: observation.runId,
      nodeType: "asset",
      normalizedIdentity: assetIdentity,
    }) ?? this.#topology.createNode({
      missionId: observation.missionId,
      runId: observation.runId,
      nodeType: "asset",
      primaryLabel: host,
      normalizedIdentity: assetIdentity,
      scopeStatus: "allowed",
      lifecycleState: "observed",
      properties: {
        address: host,
        missionTargetId: allowedTarget.id,
        transportObservation: "tcp_connect_scan",
        ...(result.hostReportedUp === true ? { hostReportedUp: true } : {}),
      },
      provenance,
      confidence: observation.confidence,
      verificationState,
      sensitivity: observation.sensitivity,
      firstSeenAt: observation.firstSeenAt,
      lastSeenAt: observation.lastSeenAt,
      evidence,
    });

    const serviceNodes: TopologyNode[] = [];
    const edgeIds: string[] = [];
    for (const port of openPorts) {
      const endpoint = `${host}:${port.port}/${port.transport}`;
      const serviceIdentity = runScopedTopologyIdentity(observation.runId, "service", endpoint);
      const service = this.#topology.repository.findNodeByIdentity({
        missionId: observation.missionId,
        runId: observation.runId,
        nodeType: "service",
        normalizedIdentity: serviceIdentity,
      }) ?? this.#topology.createNode({
        missionId: observation.missionId,
        runId: observation.runId,
        nodeType: "service",
        primaryLabel: `${port.service} · ${port.port}/${port.transport}`,
        normalizedIdentity: serviceIdentity,
        scopeStatus: "allowed",
        lifecycleState: "observed",
        properties: {
          host,
          port: port.port,
          transport: port.transport,
          state: port.state,
          service: port.service,
          ...(port.version ? {
            version: port.version,
            versionDerivation: "nmap_version_light_observation",
          } : {}),
        },
        provenance,
        confidence: observation.confidence,
        verificationState,
        sensitivity: observation.sensitivity,
        firstSeenAt: observation.firstSeenAt,
        lastSeenAt: observation.lastSeenAt,
        evidence,
      });
      serviceNodes.push(service);
      const edge = this.#topology.repository.findEdge({
        missionId: observation.missionId,
        sourceNodeId: asset.id,
        targetNodeId: service.id,
        edgeType: "exposes",
      }) ?? this.#topology.createEdge({
        missionId: observation.missionId,
        sourceNodeId: asset.id,
        targetNodeId: service.id,
        edgeType: "exposes",
        properties: {
          port: port.port,
          transport: port.transport,
          service: port.service,
          ...(port.version ? { version: port.version } : {}),
        },
        provenance,
        confidence: observation.confidence,
        verificationState,
        sensitivity: observation.sensitivity,
        firstSeenAt: observation.firstSeenAt,
        lastSeenAt: observation.lastSeenAt,
        evidence,
      });
      edgeIds.push(edge.id);
    }
    return {
      status: "materialized",
      reason: "reviewed_nmap_observation",
      assetNodeId: asset.id,
      serviceNodeIds: serviceNodes.map(({ id }) => id),
      edgeIds,
    };
  }
}
