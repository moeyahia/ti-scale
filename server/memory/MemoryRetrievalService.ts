import { createHash } from "node:crypto";
import type { MemoryRepository } from "./MemoryRepository";
import type {
  MemoryNode,
  MemorySensitivity,
  RetrievalPolicy,
  RetrievedMemory,
} from "./types";
import { validateJourney, validateSensitivity } from "./validation";
import { getMemoryControlPolicy, memoryUseAllowed } from "./MemoryControlPolicy";
import {
  memoryNodeMatchesPolicy,
  memoryScopeMatchesPolicy,
} from "./MemoryScopePolicy";
import { autonomousMemoryConfirmationEligible } from "./AutonomousMemoryInfluence";

const SENSITIVITY_RANK: Record<MemorySensitivity, number> = {
  public: 0,
  internal: 1,
  private: 2,
  restricted: 3,
};
const MAX_PERSISTED_REJECTIONS = 100;

export type MemoryRetrievalRejectionReason =
  | "missing_or_forgotten"
  | "memory_control_denied"
  | "lifecycle_status_denied"
  | "confirmation_state_denied"
  | "expired"
  | "sensitivity_denied"
  | "node_type_denied"
  | "scope_denied"
  | "journey_retention_denied"
  | "context_budget_exceeded"
  | "result_limit_exceeded";

export interface MemoryRetrievalRejection {
  /** One-way identity prevents rejected cross-engagement IDs leaking. */
  readonly candidateHash: string;
  readonly reason: MemoryRetrievalRejectionReason;
}

export interface MemoryRetrievalTrace {
  readonly items: readonly RetrievedMemory[];
  readonly rejected: readonly MemoryRetrievalRejection[];
  readonly rejectedCount: number;
  readonly rejectedTruncated: boolean;
}

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
    return this.retrieveWithTrace(query, policy).items;
  }

  retrieveWithTrace(query: string, policy: RetrievalPolicy): MemoryRetrievalTrace {
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
    if (!memoryUseAllowed(control, policy.journey)) {
      return { items: [], rejected: [], rejectedCount: 0, rejectedTruncated: false };
    }
    const ranked = new Map<string, RankedCandidate>();
    const rejected = new Map<string, MemoryRetrievalRejection>();
    const reject = (candidateId: string, reason: MemoryRetrievalRejectionReason): void => {
      const candidateHash = createHash("sha256").update(candidateId, "utf8").digest("hex");
      if (!rejected.has(candidateHash)) rejected.set(candidateHash, { candidateHash, reason });
    };
    const add = (
      node: MemoryNode,
      signal: RetrievedMemory["signals"][number],
      score: number,
      reason: string,
    ): void => {
      if (!control.operationalMemoryEnabled && node.nodeType !== "preference") {
        reject(node.id, "memory_control_denied");
        return;
      }
      const rejectionReason = this.#rejectionReason(node, policy, statuses);
      if (rejectionReason) {
        reject(node.id, rejectionReason);
        return;
      }
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
      else reject(id, "missing_or_forgotten");
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
            FROM memory_edges_safe
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
      if (selected.length >= limit) {
        reject(item.node.id, "result_limit_exceeded");
        continue;
      }
      const tokens = approximateTokens(item.node);
      if (budgetUsed + tokens > policy.contextBudget) {
        reject(item.node.id, "context_budget_exceeded");
        continue;
      }
      budgetUsed += tokens;
      selected.push({
        node: item.node,
        score: Number((item.score + item.node.confidence * 2 + (item.node.pinned ? 2 : 0)).toFixed(6)),
        relevanceReason: [...item.reasons].join("; "),
        signals: [...item.signals],
      });
    }
    const allRejected = [...rejected.values()];
    return {
      items: selected,
      rejected: allRejected.slice(0, MAX_PERSISTED_REJECTIONS),
      rejectedCount: allRejected.length,
      rejectedTruncated: allRejected.length > MAX_PERSISTED_REJECTIONS,
    };
  }

  #rejectionReason(
    node: MemoryNode,
    policy: RetrievalPolicy,
    statuses: readonly ("confirmed" | "verified")[],
  ): MemoryRetrievalRejectionReason | undefined {
    if (!statuses.includes(node.lifecycleStatus as "confirmed" | "verified")) {
      return "lifecycle_status_denied";
    }
    if (
      policy.journey === "autonomous"
      && !autonomousMemoryConfirmationEligible(node)
    ) {
      return "confirmation_state_denied";
    }
    if (node.expiresAt && Date.parse(node.expiresAt) <= Date.parse(this.#repository.now())) {
      return "expired";
    }
    if (SENSITIVITY_RANK[node.sensitivity] > SENSITIVITY_RANK[policy.maximumSensitivity]) {
      return "sensitivity_denied";
    }
    if (policy.allowedNodeTypes && !policy.allowedNodeTypes.includes(node.nodeType)) {
      return "node_type_denied";
    }
    if (!memoryScopeMatchesPolicy(this.#repository.database(), node, policy)) {
      return "scope_denied";
    }
    const retention = node.retentionPolicy;
    if (
      (retention.journeys && !retention.journeys.includes(policy.journey)) ||
      (policy.journey === "autonomous" && retention.allowAutonomous === false) ||
      (policy.journey === "guided" && retention.allowGuided === false)
    ) {
      return "journey_retention_denied";
    }
    return undefined;
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
