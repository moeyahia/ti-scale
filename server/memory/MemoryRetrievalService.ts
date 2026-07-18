import type { MemoryRepository } from "./MemoryRepository";
import type {
  MemoryNode,
  RetrievalPolicy,
  RetrievedMemory,
} from "./types";
import { validateJourney, validateSensitivity } from "./validation";
import { getMemoryControlPolicy, memoryUseAllowed } from "./MemoryControlPolicy";
import { memoryNodeMatchesPolicy } from "./MemoryScopePolicy";

function ftsQuery(source: string): string | undefined {
  const tokens = source.normalize("NFKC").match(/[\p{L}\p{N}_-]+/gu)?.slice(0, 24) ?? [];
  if (tokens.length === 0) return undefined;
  return tokens.map((token) => `"${token.replaceAll('"', '""')}"`).join(" OR ");
}

function approximateTokens(node: MemoryNode): number {
  return Math.max(1, Math.ceil((node.title.length + node.summary.length + node.body.length) / 4));
}

interface RankedCandidate {
  node: MemoryNode;
  score: number;
  signals: Set<RetrievedMemory["signals"][number]>;
  reasons: Set<string>;
}

/**
 * Local hybrid retrieval: exact identifiers, FTS5 lexical ranking, and bounded
 * graph-neighbour expansion. Scope and lifecycle policy are enforced after
 * every retrieval signal, not only after final ranking.
 */
export class MemoryRetrievalService {
  readonly #repository: MemoryRepository;

  constructor(repository: MemoryRepository) {
    this.#repository = repository;
  }

  retrieve(query: string, policy: RetrievalPolicy): readonly RetrievedMemory[] {
    validateJourney(policy.journey);
    validateSensitivity(policy.maximumSensitivity);
    if (!Number.isSafeInteger(policy.contextBudget) || policy.contextBudget < 0) {
      throw new TypeError("context budget must be a non-negative integer");
    }
    const limit = Math.min(Math.max(policy.limit ?? 20, 1), 200);
    const statuses = policy.allowedStatuses ?? ["confirmed", "verified"];
    if (statuses.some((status) => status !== "confirmed" && status !== "verified")) {
      throw new TypeError("retrieval may only include confirmed or verified memory");
    }

    const database = this.#repository.database();
    const control = getMemoryControlPolicy(database);
    if (!memoryUseAllowed(control, policy.journey)) return [];
    const ranked = new Map<string, RankedCandidate>();
    const add = (
      node: MemoryNode,
      signal: RetrievedMemory["signals"][number],
      score: number,
      reason: string,
    ): void => {
      if (!control.operationalMemoryEnabled && node.nodeType !== "preference") return;
      if (!this.#eligible(node, policy, statuses)) return;
      const existing = ranked.get(node.id);
      if (existing) {
        existing.score += score;
        existing.signals.add(signal);
        existing.reasons.add(reason);
      } else {
        ranked.set(node.id, {
          node,
          score,
          signals: new Set([signal]),
          reasons: new Set([reason]),
        });
      }
    };

    for (const id of policy.exactNodeIds ?? []) {
      const node = this.#repository.getNode(id);
      if (node) add(node, "exact", 10, "Explicitly selected by stable memory ID");
    }

    const match = policy.exactNodeIdsOnly ? undefined : ftsQuery(query);
    if (match) {
      const rows = database.prepare(`
        SELECT mn.id, bm25(memory_nodes_fts, 4.0, 2.0, 1.0) AS lexical_rank
        FROM memory_nodes_fts
        JOIN memory_nodes mn ON mn.rowid = memory_nodes_fts.rowid
        WHERE memory_nodes_fts MATCH ?
        ORDER BY lexical_rank
        LIMIT ?
      `).all(match, Math.min(limit * 5, 500)) as Array<{ id: string; lexical_rank: number }>;
      rows.forEach((row, index) => {
        const node = this.#repository.getNode(row.id);
        if (node) {
          const normalizedRank = 1 / (1 + index);
          add(node, "lexical", 5 + normalizedRank, "Title, summary, or note text matched the redacted query");
        }
      });
    } else if (!policy.exactNodeIdsOnly) {
      const rows = database.prepare(`
        SELECT id FROM memory_nodes
        WHERE lifecycle_status IN ('confirmed', 'verified')
        ORDER BY pinned DESC, updated_at DESC LIMIT ?
      `).all(Math.min(limit * 3, 300)) as Array<{ id: string }>;
      rows.forEach((row, index) => {
        const node = this.#repository.getNode(row.id);
        if (node) add(node, "recent", 1 / (1 + index), "Recent eligible memory");
      });
    }

    const depth = policy.exactNodeIdsOnly ? 0 : policy.graphDepth ?? 1;
    if (depth > 0) {
      let frontier = [...ranked.keys()];
      const visited = new Set(frontier);
      for (let currentDepth = 1; currentDepth <= depth && frontier.length > 0; currentDepth += 1) {
        const next: string[] = [];
        for (const batch of chunk(frontier, 100)) {
          const placeholders = batch.map(() => "?").join(",");
          const edges = database.prepare(`
            SELECT source_node_id, target_node_id, edge_type, explanation
            FROM memory_edges
            WHERE lifecycle_status IN ('confirmed', 'verified')
              AND (expires_at IS NULL OR expires_at > ?)
              AND (source_node_id IN (${placeholders}) OR target_node_id IN (${placeholders}))
            LIMIT 1000
          `).all(this.#repository.now(), ...batch, ...batch) as Array<{
            source_node_id: string;
            target_node_id: string;
            edge_type: string;
            explanation: string;
          }>;
          for (const edge of edges) {
            const adjacent = batch.includes(edge.source_node_id) ? edge.target_node_id : edge.source_node_id;
            const node = this.#repository.getNode(adjacent);
            const eligible = node ? this.#eligible(node, policy, statuses) : false;
            if (node && eligible) {
              add(
                node,
                "graph",
                2 / currentDepth,
                `Connected by ${edge.edge_type}: ${edge.explanation.slice(0, 240)}`,
              );
            }
            if (eligible && !visited.has(adjacent)) {
              visited.add(adjacent);
              next.push(adjacent);
            }
          }
        }
        frontier = next.slice(0, 500);
      }
    }

    let budgetUsed = 0;
    const selected: RetrievedMemory[] = [];
    const sorted = [...ranked.values()].sort((left, right) => {
      const leftScore = left.score + left.node.confidence * 2 + (left.node.pinned ? 2 : 0);
      const rightScore = right.score + right.node.confidence * 2 + (right.node.pinned ? 2 : 0);
      return rightScore - leftScore || right.node.updatedAt.localeCompare(left.node.updatedAt);
    });
    for (const item of sorted) {
      if (selected.length >= limit) break;
      const tokens = approximateTokens(item.node);
      if (budgetUsed + tokens > policy.contextBudget) continue;
      budgetUsed += tokens;
      selected.push({
        node: item.node,
        score: Number((item.score + item.node.confidence * 2 + (item.node.pinned ? 2 : 0)).toFixed(6)),
        relevanceReason: [...item.reasons].join("; "),
        signals: [...item.signals],
      });
    }
    return selected;
  }

  #eligible(
    node: MemoryNode,
    policy: RetrievalPolicy,
    statuses: readonly ("confirmed" | "verified")[],
  ): boolean {
    return memoryNodeMatchesPolicy(
      this.#repository.database(),
      node,
      { ...policy, allowedStatuses: statuses },
      this.#repository.now(),
    );
  }
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    result.push(items.slice(index, index + size));
  }
  return result;
}
