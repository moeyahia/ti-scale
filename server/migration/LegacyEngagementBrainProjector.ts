import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { MemoryRepository, type MemoryEdgeType, type MemoryLifecycle, type MemoryNodeType } from "../memory";
import type { LegacyEngagementManifest, LegacyEngagementFileKind } from "./LegacyEngagementDiscovery";
import { parseLegacyReconSemantics, type LegacyReconHostObservation } from "./LegacyReconSemanticParser";

export interface LegacyEngagementProjectionArtifact {
  readonly artifactId: string;
  readonly relativePath: string;
  readonly kind: LegacyEngagementFileKind | "manifest";
  readonly contentHash: string;
  readonly evidenceCandidateId?: string;
}

export interface LegacyEngagementBrainProjectionInput {
  readonly migrationId: string;
  readonly manifest: LegacyEngagementManifest;
  readonly missionId: string;
  readonly runId: string;
  readonly manifestArtifactId: string;
  readonly artifacts: readonly LegacyEngagementProjectionArtifact[];
}

export interface LegacyEngagementBrainProjectionResult {
  readonly nodeIds: readonly string[];
  readonly edgeIds: readonly string[];
}

function stableId(prefix: string, ...parts: string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part).update("\0");
  return `${prefix}_${hash.digest("hex").slice(0, 40)}`;
}

function basename(path: string): string {
  return path.split("/").at(-1) || "Imported artifact";
}

/**
 * Projects only redacted, typed canonical metadata. Raw historical payloads stay
 * in the protected migration backup and are referenced by opaque canonical IDs.
 */
export class LegacyEngagementBrainProjector {
  readonly #memory: MemoryRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.#memory = new MemoryRepository(database, { clock });
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS legacy_engagement_brain_nodes (
        migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
        manifest_id TEXT NOT NULL,
        node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (migration_id, node_id)
      ) STRICT;
      CREATE INDEX IF NOT EXISTS idx_legacy_engagement_brain_manifest
        ON legacy_engagement_brain_nodes(manifest_id, node_id);
    `);
  }

  project(input: LegacyEngagementBrainProjectionInput): LegacyEngagementBrainProjectionResult {
    const createdAt = this.clock().toISOString();
    const source = {
      sourceType: "legacy_engagement_manifest",
      sourceId: input.manifest.id,
      sourceHash: input.manifest.sha256,
      acquiredAt: input.manifest.modifiedAt,
    } as const;
    const scope = { kind: "mission" as const, missionId: input.missionId };
    const nodeIds: string[] = [];
    const edgeIds: string[] = [];
    const ensureNode = (values: {
      id: string;
      nodeType: MemoryNodeType;
      title: string;
      summary: string;
      body: string;
      lifecycle?: Exclude<MemoryLifecycle, "forgotten">;
      confidence?: number;
      sourceType?: string;
      sourceId?: string;
      sourceHash?: string;
      sources?: readonly {
        sourceType: string;
        sourceId: string;
        sourceHash?: string;
        acquiredAt: string;
      }[];
      provenanceExplanation?: string;
    }): string => {
      const existing = this.#memory.getNode(values.id, true);
      if (!existing) {
        this.#memory.createNode({
          id: values.id,
          nodeType: values.nodeType,
          title: values.title,
          summary: values.summary,
          body: values.body,
          scope,
          sensitivity: "restricted",
          confidence: values.confidence ?? 1,
          lifecycleStatus: values.lifecycle ?? "verified",
          confirmationState: values.lifecycle === "candidate" ? "pending" : "not_required",
          provenance: {
            method: "imported",
            explanation: values.provenanceExplanation ?? "Projected from a hash-verified historical engagement manifest; authorization and claim verification remain separate.",
            sources: values.sources ?? [{
              sourceType: values.sourceType ?? source.sourceType,
              sourceId: values.sourceId ?? source.sourceId,
              sourceHash: values.sourceHash ?? source.sourceHash,
              acquiredAt: source.acquiredAt,
            }],
          },
          authorType: "import",
          authorId: "import:legacy-engagement",
          retentionPolicy: { allowAutonomous: false, allowGuided: true },
        });
      }
      this.database.prepare(`
        INSERT OR IGNORE INTO legacy_engagement_brain_nodes (
          migration_id, manifest_id, node_id, created_at
        ) VALUES (?, ?, ?, ?)
      `).run(input.migrationId, input.manifest.id, values.id, createdAt);
      nodeIds.push(values.id);
      return values.id;
    };
    const ensureEdge = (values: {
      sourceNodeId: string;
      targetNodeId: string;
      edgeType: MemoryEdgeType;
      title: string;
      summary: string;
      lifecycle?: Exclude<MemoryLifecycle, "forgotten">;
      confidence?: number;
      sources?: readonly {
        sourceType: string;
        sourceId: string;
        sourceHash?: string;
        acquiredAt: string;
      }[];
      provenanceExplanation?: string;
    }): string => {
      const id = stableId("medge_legacy", values.sourceNodeId, values.edgeType, values.targetNodeId);
      const existing = this.database.prepare("SELECT id FROM memory_edges WHERE id = ?").get(id);
      if (!existing) {
        this.#memory.createEdge({
          id,
          sourceNodeId: values.sourceNodeId,
          targetNodeId: values.targetNodeId,
          edgeType: values.edgeType,
          title: values.title,
          summary: values.summary,
          scope,
          sensitivity: "restricted",
          confidence: values.confidence ?? 1,
          lifecycleStatus: values.lifecycle ?? "verified",
          provenance: {
            method: "imported",
            explanation: values.provenanceExplanation ?? "The relationship was deterministically reconstructed from canonical imported records.",
            sources: values.sources ?? [source],
          },
          explanation: values.summary,
          authorType: "import",
          authorId: "import:legacy-engagement",
        });
      }
      edgeIds.push(id);
      return id;
    };

    const missionNode = ensureNode({
      id: stableId("mem_legacy_mission", input.missionId),
      nodeType: "mission",
      title: input.manifest.engagementName,
      summary: "Imported historical engagement. Its authorization and outcome require operator reconciliation.",
      body: `Canonical mission: ${input.missionId}. Open the mission workspace for protected records and provenance.`,
    });
    const runNode = ensureNode({
      id: stableId("mem_legacy_run", input.runId),
      nodeType: "run",
      title: `${input.manifest.engagementName} — imported history`,
      summary: "Historical run is blocked from execution and retained for review only.",
      body: `Canonical run: ${input.runId}. No execution permission was inferred by import.`,
    });
    const sourceNode = ensureNode({
      id: stableId("mem_legacy_source", input.manifest.id),
      nodeType: "source",
      title: `${input.manifest.engagementName} source manifest`,
      summary: `${input.manifest.files.length} hash-verified, classified historical files were inventoried.`,
      body: "The protected source backup remains authoritative for raw bytes; this note retains metadata only.",
    });
    ensureEdge({ sourceNodeId: runNode, targetNodeId: missionNode, edgeType: "belongs_to", title: "Run belongs to mission", summary: "The imported historical run belongs to this canonical mission." });
    ensureEdge({ sourceNodeId: missionNode, targetNodeId: sourceNode, edgeType: "derived_from", title: "Mission derived from source", summary: "The canonical mission was reconstructed from this hash-verified engagement manifest." });

    const allArtifacts: LegacyEngagementProjectionArtifact[] = [
      {
        artifactId: input.manifestArtifactId,
        relativePath: "engagement-manifest.json",
        kind: "manifest",
        contentHash: input.manifest.sha256,
      },
      ...input.artifacts,
    ];
    const artifactNodesByRelativePath = new Map<string, { artifact: LegacyEngagementProjectionArtifact; nodeId: string }>();
    for (const artifact of allArtifacts) {
      const artifactNode = ensureNode({
        id: stableId("mem_legacy_artifact", artifact.artifactId),
        nodeType: "artifact",
        title: basename(artifact.relativePath),
        summary: `Imported ${artifact.kind} artifact metadata; raw content remains in protected storage.`,
        body: `Canonical artifact: ${artifact.artifactId}. Content hash: ${artifact.contentHash}.`,
        sourceType: "artifact",
        sourceId: artifact.artifactId,
        sourceHash: artifact.contentHash,
      });
      artifactNodesByRelativePath.set(artifact.relativePath, { artifact, nodeId: artifactNode });
      ensureEdge({ sourceNodeId: runNode, targetNodeId: artifactNode, edgeType: "produced", title: "Run produced artifact", summary: "The historical engagement inventory associates this artifact with the imported run." });
      if (artifact.evidenceCandidateId) {
        const evidenceNode = ensureNode({
          id: stableId("mem_legacy_evidence", artifact.evidenceCandidateId),
          nodeType: "evidence",
          title: `Evidence candidate: ${basename(artifact.relativePath)}`,
          summary: "Imported artifact is a reviewable evidence candidate and is not verified evidence.",
          body: `Canonical evidence candidate: ${artifact.evidenceCandidateId}.`,
          lifecycle: "candidate",
          confidence: 0.4,
          sourceType: "evidence_candidate",
          sourceId: artifact.evidenceCandidateId,
          sourceHash: artifact.contentHash,
        });
        ensureEdge({ sourceNodeId: evidenceNode, targetNodeId: artifactNode, edgeType: "derived_from", title: "Candidate derived from artifact", summary: "The reviewable evidence candidate was derived from this immutable artifact metadata.", lifecycle: "candidate", confidence: 0.4 });
      }
    }

    const recon = parseLegacyReconSemantics(input.manifest);
    const groupedHosts = new Map<string, {
      address: string;
      hostnames: Set<string>;
      statuses: Set<string>;
      osHints: Set<string>;
      observations: LegacyReconHostObservation[];
      services: Map<string, {
        port: number;
        transport: "tcp" | "udp" | "sctp";
        states: Set<string>;
        names: Set<string>;
        products: Set<string>;
        observations: LegacyReconHostObservation[];
      }>;
    }>();
    for (const observation of recon.hosts) {
      const key = observation.address.toLocaleLowerCase();
      const host: NonNullable<ReturnType<typeof groupedHosts.get>> = groupedHosts.get(key) ?? {
        address: observation.address,
        hostnames: new Set<string>(),
        statuses: new Set<string>(),
        osHints: new Set<string>(),
        observations: [],
        services: new Map(),
      };
      if (observation.hostname) host.hostnames.add(observation.hostname);
      host.statuses.add(observation.hostStatus);
      observation.osHints.forEach((hint) => host.osHints.add(hint));
      host.observations.push(observation);
      for (const service of observation.services) {
        const serviceKey = `${service.port}/${service.transport}`;
        const grouped: NonNullable<ReturnType<typeof host.services.get>> = host.services.get(serviceKey) ?? {
          port: service.port,
          transport: service.transport,
          states: new Set<string>(),
          names: new Set<string>(),
          products: new Set<string>(),
          observations: [],
        };
        grouped.states.add(service.state);
        if (service.serviceName) grouped.names.add(service.serviceName);
        if (service.productVersion) grouped.products.add(service.productVersion);
        grouped.observations.push(observation);
        host.services.set(serviceKey, grouped);
      }
      groupedHosts.set(key, host);
    }
    const sourcesFor = (observations: readonly LegacyReconHostObservation[]) => [...new Map(observations.flatMap((observation) => {
      const linked = artifactNodesByRelativePath.get(observation.sourceRelativePath);
      if (!linked) return [];
      const value = {
        sourceType: "artifact",
        sourceId: linked.artifact.artifactId,
        sourceHash: observation.sourceHash,
        acquiredAt: observation.observedAt,
      };
      return [[`${value.sourceId}:${value.sourceHash}`, value] as const];
    })).values()].sort((left, right) => left.sourceId.localeCompare(right.sourceId));
    const historicalProvenance = "A bounded deterministic parser extracted this observation from hash-verified historical Nmap output. It proves what the artifact reported, not that the asset or service is reachable now.";
    for (const host of [...groupedHosts.values()].sort((left, right) => left.address.localeCompare(right.address))) {
      const hostSources = sourcesFor(host.observations);
      if (hostSources.length === 0) continue;
      const hostnames = [...host.hostnames].sort();
      const osHints = [...host.osHints].sort();
      const assetNode = ensureNode({
        id: stableId("mem_legacy_asset_observation", input.missionId, host.address.toLocaleLowerCase()),
        nodeType: "asset",
        title: `Historical asset observation — ${host.address}`,
        summary: `Hash-verified historical recon reported ${host.address}${hostnames.length ? ` as ${hostnames.join(", ")}` : ""}; current reachability is unverified.`,
        body: [
          `Reported address: ${host.address}.`,
          hostnames.length ? `Reported hostnames: ${hostnames.join(", ")}.` : "No hostname was reported.",
          `Historical host state: ${[...host.statuses].sort().join(", ")}.`,
          osHints.length ? `Historical OS hints: ${osHints.join("; ")}.` : "No OS hint was retained.",
          "Treat this as historical context until a current authorized run corroborates it.",
        ].join(" "),
        sources: hostSources,
        provenanceExplanation: historicalProvenance,
      });
      ensureEdge({
        sourceNodeId: assetNode,
        targetNodeId: missionNode,
        edgeType: "mentioned_in",
        title: "Asset reported in historical mission",
        summary: "Hash-verified recon associated this historical asset observation with the imported mission; current authorization and reachability are not inferred.",
        sources: hostSources,
        provenanceExplanation: historicalProvenance,
      });
      for (const observation of host.observations) {
        const linked = artifactNodesByRelativePath.get(observation.sourceRelativePath);
        if (!linked) continue;
        const observationSources = sourcesFor([observation]);
        ensureEdge({
          sourceNodeId: assetNode,
          targetNodeId: linked.nodeId,
          edgeType: "derived_from",
          title: "Asset observation derived from recon artifact",
          summary: "This historical asset observation was extracted from the linked immutable recon artifact.",
          sources: observationSources,
          provenanceExplanation: historicalProvenance,
        });
      }
      for (const service of [...host.services.values()].sort((left, right) => left.port - right.port || left.transport.localeCompare(right.transport))) {
        const serviceSources = sourcesFor(service.observations);
        const names = [...service.names].sort();
        const products = [...service.products].sort();
        const serviceNode = ensureNode({
          id: stableId("mem_legacy_service_observation", input.missionId, host.address.toLocaleLowerCase(), String(service.port), service.transport),
          nodeType: "entity",
          title: `Historical service observation — ${host.address}:${service.port}/${service.transport}`,
          summary: `Historical recon reported ${names[0] ?? "a service"} on ${host.address}:${service.port}/${service.transport}; current availability is unverified.`,
          body: [
            `Reported states: ${[...service.states].sort().join(", ")}.`,
            names.length ? `Reported service names: ${names.join(", ")}.` : "No service name was retained.",
            products.length ? `Reported product/version text: ${products.join("; ")}.` : "No product/version text was retained.",
            "Treat this as a historical observation until current evidence corroborates it.",
          ].join(" "),
          sources: serviceSources,
          provenanceExplanation: historicalProvenance,
        });
        ensureEdge({
          sourceNodeId: serviceNode,
          targetNodeId: assetNode,
          edgeType: "belongs_to",
          title: "Service reported on asset",
          summary: "The historical recon output reported this service on the linked asset observation.",
          sources: serviceSources,
          provenanceExplanation: historicalProvenance,
        });
        for (const observation of service.observations) {
          const linked = artifactNodesByRelativePath.get(observation.sourceRelativePath);
          if (!linked) continue;
          const observationSources = sourcesFor([observation]);
          ensureEdge({
            sourceNodeId: serviceNode,
            targetNodeId: linked.nodeId,
            edgeType: "derived_from",
            title: "Service observation derived from recon artifact",
            summary: "This historical service observation was extracted from the linked immutable recon artifact.",
            sources: observationSources,
            provenanceExplanation: historicalProvenance,
          });
        }
      }
    }
    return { nodeIds: [...new Set(nodeIds)], edgeIds: [...new Set(edgeIds)] };
  }
}
