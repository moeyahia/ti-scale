#!/usr/bin/env bun
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../server/db";
import { HistoricalAttackKnowledgeExtractionService } from
  "../server/migration/HistoricalAttackKnowledgeExtractionService";
import { discoverLegacyEngagements } from
  "../server/migration/LegacyEngagementDiscovery";

const DEFAULT_DATABASE = "/var/lib/ti-scale/data/ti-scale.sqlite";
const AUDIT_HMAC_KEY = "ti-scale-local-historical-link-audit-non-production-v1";

interface ConfiguredMigrationRow {
  readonly id: string;
  readonly source_roots_json: string;
  readonly settle_cutoff_at: string | null;
}

interface IsolatedRow {
  readonly id: string;
  readonly node_type: string;
  readonly title: string;
  readonly content_fingerprint: string;
}

interface LiveCandidateRow {
  readonly content_fingerprint: string;
  readonly candidate_type: string;
  readonly title: string;
  readonly status: string;
  readonly proposed_node_id: string | null;
}

interface RoleRow {
  readonly bundle_id: string;
  readonly role: string;
  readonly content_fingerprint: string;
  readonly candidate_type: string;
  readonly title: string;
}

interface EdgeRow {
  readonly bundle_id: string;
  readonly source_role: string;
  readonly target_role: string;
  readonly edge_type: string;
}

function configuredMigrations(database: SqliteDatabase): readonly ConfiguredMigrationRow[] {
  return database.prepare(`
    SELECT id, source_roots_json, settle_cutoff_at
    FROM legacy_migration_runs
    WHERE status = 'completed' AND brain_projection_mode = 'attack-knowledge-only'
    ORDER BY started_at, id
  `).all() as ConfiguredMigrationRow[];
}

function isolatedNodes(database: SqliteDatabase): readonly IsolatedRow[] {
  return database.prepare(`
    WITH connected AS (
      SELECT source_node_id AS id FROM memory_edges
      WHERE lifecycle_status IN ('confirmed', 'verified')
      UNION
      SELECT target_node_id AS id FROM memory_edges
      WHERE lifecycle_status IN ('confirmed', 'verified')
    )
    SELECT n.id, n.node_type, n.title, registry.content_fingerprint
    FROM memory_nodes n
    JOIN memory_candidates candidate
      ON candidate.proposed_node_id = n.id AND candidate.status = 'confirmed'
    JOIN attack_knowledge_candidate_registry registry
      ON registry.candidate_id = candidate.id
    WHERE n.scope = 'global'
      AND n.lifecycle_status = 'verified'
      AND n.engagement_id IS NULL
      AND n.mission_id IS NULL
      AND n.id NOT IN (SELECT id FROM connected)
    ORDER BY n.node_type, n.title, n.id
  `).all() as IsolatedRow[];
}

function liveCandidateMap(database: SqliteDatabase): ReadonlyMap<string, LiveCandidateRow> {
  const rows = database.prepare(`
    SELECT registry.content_fingerprint, candidate.candidate_type, candidate.title,
      candidate.status, candidate.proposed_node_id
    FROM attack_knowledge_candidate_registry registry
    JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
    ORDER BY registry.content_fingerprint
  `).all() as LiveCandidateRow[];
  return new Map(rows.map((row) => [row.content_fingerprint, row]));
}

function integer(database: SqliteDatabase, sql: string): number {
  const row = database.prepare(sql).get() as { readonly count: number };
  return Number(row.count);
}

function increment(target: Record<string, number>, key: string, amount = 1): void {
  target[key] = (target[key] ?? 0) + amount;
}

async function main(): Promise<void> {
  const databasePath = process.argv[2] ?? DEFAULT_DATABASE;
  const live = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
  });
  live.pragma("query_only = ON");
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "ti-scale-historical-link-audit-"));
  const staged = createDatabaseConnection({ filename: join(temporaryDirectory, "audit.sqlite") });
  try {
    migrateDatabase(staged);
    const migrations = configuredMigrations(live);
    const roots = new Set<string>();
    let settledCutoffAt: string | undefined;
    for (const migration of migrations) {
      const configured = JSON.parse(migration.source_roots_json) as unknown;
      if (!Array.isArray(configured) || configured.some((root) => typeof root !== "string")) {
        throw new Error("A configured historical migration contains an invalid source root list");
      }
      configured.forEach((root) => roots.add(root as string));
      if (migration.settle_cutoff_at &&
          (settledCutoffAt === undefined || migration.settle_cutoff_at < settledCutoffAt)) {
        settledCutoffAt = migration.settle_cutoff_at;
      }
    }
    const discovery = await discoverLegacyEngagements([...roots].sort(), {
      rootMode: "self",
      ...(settledCutoffAt ? { settledSourceCutoffAt: settledCutoffAt } : {}),
    });

    const dryRunService = new HistoricalAttackKnowledgeExtractionService(live, {
      receiptHmacKey: AUDIT_HMAC_KEY,
    });
    const stagingService = new HistoricalAttackKnowledgeExtractionService(staged, {
      receiptHmacKey: AUDIT_HMAC_KEY,
    });
    const dryTotals = {
      filesDiscovered: 0,
      filesParsed: 0,
      filesSkipped: 0,
      filesQuarantined: 0,
      bytesParsed: 0,
      semanticFactsParsed: 0,
      ambiguousFragments: 0,
      compilerBundles: 0,
      candidateCreates: 0,
      candidateReuses: 0,
      sourceEvidenceCandidates: 0,
      sourceBundleLinks: 0,
      nodeTypeCounts: {} as Record<string, number>,
      edgeTypeCounts: {} as Record<string, number>,
      issueCounts: {} as Record<string, number>,
    };

    const runAllPages = (
      service: HistoricalAttackKnowledgeExtractionService,
      dryRun: boolean,
      manifest: (typeof discovery.manifests)[number],
    ): void => {
      let cursor: string | undefined;
      for (let page = 0; page < 10_000; page += 1) {
        const result = service.extract(manifest, {
          dryRun,
          ...(cursor ? { resumeAfterSourceKey: cursor } : {}),
        });
        if (dryRun) {
          dryTotals.filesDiscovered = Math.max(dryTotals.filesDiscovered, result.filesDiscovered);
          dryTotals.filesParsed += result.filesParsed;
          dryTotals.filesSkipped += result.filesSkipped;
          dryTotals.filesQuarantined += result.filesQuarantined;
          dryTotals.bytesParsed += result.bytesParsed;
          dryTotals.semanticFactsParsed += result.semanticFactsParsed;
          dryTotals.ambiguousFragments += result.ambiguousFragments;
          dryTotals.compilerBundles += result.compilerBundlesStaged;
          dryTotals.candidateCreates += result.candidatesCreated;
          dryTotals.candidateReuses += result.candidatesReused;
          dryTotals.sourceEvidenceCandidates += result.sourceEvidenceCandidatesCreated +
            result.sourceEvidenceCandidatesReused;
          dryTotals.sourceBundleLinks += result.sourceBundleLinks;
          Object.entries(result.nodeTypeCounts).forEach(([key, value]) =>
            increment(dryTotals.nodeTypeCounts, key, value));
          Object.entries(result.edgeTypeCounts).forEach(([key, value]) =>
            increment(dryTotals.edgeTypeCounts, key, value));
          result.issues.forEach((issue) => increment(
            dryTotals.issueCounts,
            `${issue.disposition}:${issue.reason}`,
            issue.count ?? 1,
          ));
        }
        if (result.status === "completed") return;
        if (!result.nextResumeAfterSourceKey || result.nextResumeAfterSourceKey === cursor) {
          throw new Error("Historical extraction cursor did not advance");
        }
        cursor = result.nextResumeAfterSourceKey;
      }
      throw new Error("Historical extraction exceeded the audit page bound");
    };

    for (const manifest of discovery.manifests) {
      runAllPages(dryRunService, true, manifest);
      runAllPages(stagingService, false, manifest);
    }

    const isolated = isolatedNodes(live);
    const isolatedByFingerprint = new Map(isolated.map((node) => [node.content_fingerprint, node]));
    const liveCandidates = liveCandidateMap(live);
    const roles = staged.prepare(`
      SELECT bundle_candidate.bundle_id, bundle_candidate.role,
        bundle_candidate.content_fingerprint, candidate.candidate_type, candidate.title
      FROM attack_knowledge_bundle_candidates bundle_candidate
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = bundle_candidate.content_fingerprint
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      ORDER BY bundle_candidate.bundle_id, bundle_candidate.role
    `).all() as RoleRow[];
    const roleMap = new Map(roles.map((role) => [`${role.bundle_id}\0${role.role}`, role]));
    const edges = staged.prepare(`
      SELECT bundle_id, source_role, target_role, edge_type
      FROM attack_knowledge_bundle_edges
      ORDER BY bundle_id, edge_key
    `).all() as EdgeRow[];
    const sourceBoundBundles = new Set((staged.prepare(`
      SELECT DISTINCT bundle_id FROM historical_attack_knowledge_bundle_sources
      ORDER BY bundle_id
    `).all() as Array<{ readonly bundle_id: string }>).map(({ bundle_id }) => bundle_id));
    const verifiedSourceHashes = new Set((live.prepare(`
      SELECT DISTINCT source_sha256
      FROM legacy_migration_source_objects
      WHERE object_kind = 'accepted' AND verification_status = 'verified_reference'
      ORDER BY source_sha256
    `).all() as Array<{ readonly source_sha256: string }>).map(({ source_sha256 }) => source_sha256));
    const verifiedReferenceBundles = new Set((staged.prepare(`
      SELECT bundle_id, source_hash
      FROM historical_attack_knowledge_bundle_sources
      ORDER BY bundle_id, source_hash
    `).all() as Array<{ readonly bundle_id: string; readonly source_hash: string }>)
      .filter(({ source_hash }) => verifiedSourceHashes.has(source_hash))
      .map(({ bundle_id }) => bundle_id));

    const proposals = new Map<string, {
      isolatedType: string;
      isolatedTitle: string;
      direction: "outbound" | "inbound";
      edgeType: string;
      counterpartType: string;
      counterpartTitle: string;
      counterpartLiveStatus: string;
      counterpartNodeAvailable: boolean;
      hashBoundSourceBundles: Set<string>;
      verifiedReferenceSourceBundles: Set<string>;
    }>();
    for (const edge of edges) {
      const source = roleMap.get(`${edge.bundle_id}\0${edge.source_role}`);
      const target = roleMap.get(`${edge.bundle_id}\0${edge.target_role}`);
      if (!source || !target || source.content_fingerprint === target.content_fingerprint) continue;
      for (const direction of ["outbound", "inbound"] as const) {
        const endpoint = direction === "outbound" ? source : target;
        const counterpart = direction === "outbound" ? target : source;
        const isolatedNode = isolatedByFingerprint.get(endpoint.content_fingerprint);
        if (!isolatedNode) continue;
        const liveCounterpart = liveCandidates.get(counterpart.content_fingerprint);
        const key = [endpoint.content_fingerprint, direction, edge.edge_type,
          counterpart.content_fingerprint].join("\0");
        const proposal = proposals.get(key) ?? {
          isolatedType: isolatedNode.node_type,
          isolatedTitle: isolatedNode.title,
          direction,
          edgeType: edge.edge_type,
          counterpartType: counterpart.candidate_type,
          counterpartTitle: counterpart.title,
          counterpartLiveStatus: liveCounterpart?.status ?? "not_staged_live",
          counterpartNodeAvailable: Boolean(liveCounterpart?.proposed_node_id),
          hashBoundSourceBundles: new Set<string>(),
          verifiedReferenceSourceBundles: new Set<string>(),
        };
        if (sourceBoundBundles.has(edge.bundle_id)) proposal.hashBoundSourceBundles.add(edge.bundle_id);
        if (verifiedReferenceBundles.has(edge.bundle_id)) {
          proposal.verifiedReferenceSourceBundles.add(edge.bundle_id);
        }
        proposals.set(key, proposal);
      }
    }

    const proposedByNode = new Map<string, Array<{
      direction: string;
      edgeType: string;
      counterpartType: string;
      counterpartTitle: string;
      counterpartLiveStatus: string;
      counterpartNodeAvailable: boolean;
      sourceBundleCount: number;
      verifiedReferenceSourceBundleCount: number;
    }>>();
    const proposedEdgeTypeCounts: Record<string, number> = {};
    for (const proposal of proposals.values()) {
      increment(proposedEdgeTypeCounts, proposal.edgeType);
      const key = `${proposal.isolatedType}\0${proposal.isolatedTitle}`;
      const list = proposedByNode.get(key) ?? [];
      list.push({
        direction: proposal.direction,
        edgeType: proposal.edgeType,
        counterpartType: proposal.counterpartType,
        counterpartTitle: proposal.counterpartTitle,
        counterpartLiveStatus: proposal.counterpartLiveStatus,
        counterpartNodeAvailable: proposal.counterpartNodeAvailable,
        sourceBundleCount: proposal.hashBoundSourceBundles.size,
        verifiedReferenceSourceBundleCount: proposal.verifiedReferenceSourceBundles.size,
      });
      proposedByNode.set(key, list);
    }

    const isolatedInventory = isolated.map((node) => {
      const key = `${node.node_type}\0${node.title}`;
      const links = (proposedByNode.get(key) ?? []).sort((left, right) =>
        left.edgeType.localeCompare(right.edgeType) ||
        left.counterpartType.localeCompare(right.counterpartType) ||
        left.counterpartTitle.localeCompare(right.counterpartTitle));
      let reason: string | undefined;
      if (links.length === 0) {
        if (node.node_type === "script_artifact") {
          reason = "No exact same-source procedure/product relationship was extracted for this script hash.";
        } else if (["attack_technique", "attack_vector"].includes(node.node_type)) {
          reason = "Historical mention remains product/procedure-ambiguous in the configured hash-pinned source.";
        } else {
          reason = "No unambiguous same-source relationship was extracted under the current taxonomy.";
        }
      }
      return {
        nodeType: node.node_type,
        title: node.title,
        proposedLinkCount: links.length,
        links,
        ...(reason ? { unresolvedReason: reason } : {}),
      };
    });

    const configuredParentCandidates = [
      "/var/lib/chillspwn/workspaces/htb/boxes",
      "/var/lib/chillspwn/workspaces/engagements",
    ];
    const configuredSet = new Set([...roots]);
    const parentCoverage = configuredParentCandidates.map((parent) => ({
      sourceClass: parent.endsWith("/boxes") ? "htb_boxes" : "engagements",
      configuredAsHistoricalRoot: configuredSet.has(parent),
    }));

    const report = {
      schemaVersion: "ti_scale.historical_attack_link_audit/v1",
      safety: {
        liveDatabaseMode: "read_only_query_only",
        sourceMode: "read_only_hash_pinned",
        stagingDatabase: "disposable_local",
        liveDatabaseWrites: false,
        liveVaultWrites: false,
        automaticPromotion: false,
      },
      configuredSources: {
        migrationRuns: migrations.length,
        uniqueRoots: roots.size,
        manifests: discovery.manifests.length,
        rootAliases: discovery.roots.aliases.length,
        missingRoots: discovery.roots.missing.length,
        acceptedFiles: discovery.manifests.reduce((sum, manifest) => sum + manifest.files.length, 0),
        discoveryQuarantines: discovery.excluded.length,
        deferredFiles: discovery.deferred.length,
        parentCoverage,
      },
      currentGraph: {
        verifiedGlobalReusableNodes: integer(live, `
          SELECT COUNT(*) AS count FROM memory_nodes
          WHERE scope = 'global' AND lifecycle_status = 'verified'
            AND engagement_id IS NULL AND mission_id IS NULL
        `),
        verifiedRelationships: integer(live, `
          WITH reusable AS (
            SELECT id FROM memory_nodes
            WHERE scope = 'global' AND lifecycle_status = 'verified'
              AND engagement_id IS NULL AND mission_id IS NULL
          )
          SELECT COUNT(*) AS count FROM memory_edges edge
          JOIN reusable source ON source.id = edge.source_node_id
          JOIN reusable target ON target.id = edge.target_node_id
          WHERE edge.lifecycle_status IN ('confirmed', 'verified')
        `),
        isolatedNodes: isolated.length,
      },
      dryRun: {
        ...dryTotals,
        nodeTypeCounts: Object.fromEntries(Object.entries(dryTotals.nodeTypeCounts).sort()),
        edgeTypeCounts: Object.fromEntries(Object.entries(dryTotals.edgeTypeCounts).sort()),
        issueCounts: Object.fromEntries(Object.entries(dryTotals.issueCounts).sort()),
      },
      relationshipProposal: {
        isolatedNodesWithProposedLinks: isolatedInventory.filter((node) => node.proposedLinkCount > 0).length,
        isolatedNodesWithExistingVerifiedCounterparts: isolatedInventory.filter((node) =>
          node.links.some((link) => link.counterpartNodeAvailable &&
            link.verifiedReferenceSourceBundleCount > 0)).length,
        unresolvedIsolatedNodes: isolatedInventory.filter((node) => node.proposedLinkCount === 0).length,
        uniqueProposedLinks: proposals.size,
        edgeTypeCounts: Object.fromEntries(Object.entries(proposedEdgeTypeCounts).sort()),
        nodes: isolatedInventory,
      },
      liveMigrationSafety: {
        safeToStageAsCandidates: true,
        safeToAutoMaterializeEdges: false,
        requiredBeforeLiveMutation: [
          "independent source-evidence review and hash revalidation",
          "operator confirmation of every counterpart candidate",
          "promotion-service dry run proving both endpoints are verified",
          "database backup, reconciliation receipt, Vault projection preview, and rollback rehearsal",
        ],
      },
    };
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } finally {
    staged.close();
    live.close();
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

await main();
