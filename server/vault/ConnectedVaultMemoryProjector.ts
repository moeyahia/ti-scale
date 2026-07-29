import type { SqliteDatabase } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import { MemoryRepository } from "../memory";
import { ObsidianVaultBridge } from "./ObsidianVaultBridge";

export interface ConnectedVaultProjectionReport {
  readonly requestedNodeIds: readonly string[];
  /**
   * Nodes retained canonically but intentionally withheld from this Vault by
   * the active operator policy. This makes consent-bound candidate skips
   * inspectable instead of indistinguishable from a dropped callback.
   */
  readonly skippedByPolicyNodeIds: readonly string[];
  readonly attempted: number;
  readonly synchronized: number;
  readonly attentionRequired: number;
  readonly skippedByPolicy: number;
  readonly failures: number;
}

export interface ConnectedVaultRevocationReport {
  readonly requestedNodeIds: readonly string[];
  readonly removedNodeIds: readonly string[];
  readonly failures: number;
}

/**
 * Post-commit projection sink for canonical runtime memory. SQLite remains
 * authoritative: an unavailable or conflicted optional Vault is recorded and
 * degraded without rolling back mission/run completion.
 */
export class ConnectedVaultMemoryProjector {
  readonly #memory: MemoryRepository;
  readonly #audit: AuditTrailWriter;
  readonly #clock: () => Date;

  constructor(
    readonly database: SqliteDatabase,
    readonly bridge: ObsidianVaultBridge,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#memory = new MemoryRepository(database, { clock: options.clock });
    this.#audit = new AuditTrailWriter(database);
    this.#clock = options.clock ?? (() => new Date());
  }

  project(nodeIds: readonly string[]): ConnectedVaultProjectionReport {
    const requestedNodeIds = [...new Set(nodeIds)];
    const missionReports = new Map<string, {
      attempted: number;
      synchronized: number;
      attentionRequired: number;
      skippedByPolicy: number;
      skippedByPolicyNodeIds: Set<string>;
      failures: number;
      nodeIds: Set<string>;
      connectionIds: Set<string>;
    }>();
    const failedConnectionIds = new Set<string>();
    const report = {
      requestedNodeIds,
      skippedByPolicyNodeIds: [] as string[],
      attempted: 0,
      synchronized: 0,
      attentionRequired: 0,
      skippedByPolicy: 0,
      failures: 0,
    };
    const nodes = requestedNodeIds.flatMap((nodeId) => {
      const node = this.#memory.getNode(nodeId);
      return node ? [node] : [];
    });
    const connections = this.database.prepare(`
      SELECT id FROM vault_connections WHERE status = 'connected' ORDER BY id
    `).all() as Array<{ id: string }>;

    for (const connection of connections) {
      for (const node of nodes) {
        // Reusable lessons can remain engagement-scoped while being produced
        // by a mission-scoped evaluation. Follow their canonical graph edge so
        // policy skips are still persisted in the originating mission audit.
        const nodeMissionReports = this.#missionIdsForNode(node.id, node.scope)
          .map((missionId) => this.#missionReport(missionReports, missionId));
        for (const missionReport of nodeMissionReports) {
          missionReport.nodeIds.add(node.id);
          missionReport.connectionIds.add(connection.id);
        }
        try {
          // Use the bridge's live policy boundary for only this node. A full
          // exportable-ID scan can traverse tens of thousands of unrelated
          // notes for every terminal event and would make projection latency
          // scale with the entire Vault instead of this committed change set.
          this.bridge.assertConnectionNodeAllowed(connection.id, node.id);
        } catch (error) {
          if (!this.#isPolicyExclusion(error)) {
            report.failures += 1;
            for (const missionReport of nodeMissionReports) missionReport.failures += 1;
            failedConnectionIds.add(connection.id);
            this.#markConnectionDegraded(connection.id);
            continue;
          }
          report.skippedByPolicy += 1;
          report.skippedByPolicyNodeIds.push(node.id);
          for (const missionReport of nodeMissionReports) {
            missionReport.skippedByPolicy += 1;
            missionReport.skippedByPolicyNodeIds.add(node.id);
          }
          continue;
        }
        report.attempted += 1;
        for (const missionReport of nodeMissionReports) missionReport.attempted += 1;
        try {
          // Runtime and maintenance projection is deliberately one-way. A
          // vault-ahead note is surfaced for operator review and is never
          // imported under a system actor or mistaken for an operator edit.
          const result = this.bridge.exportNode(connection.id, node.id);
          if (result.status === "synced") {
            report.synchronized += 1;
            for (const missionReport of nodeMissionReports) missionReport.synchronized += 1;
          } else {
            report.attentionRequired += 1;
            for (const missionReport of nodeMissionReports) missionReport.attentionRequired += 1;
          }
        } catch {
          report.failures += 1;
          for (const missionReport of nodeMissionReports) missionReport.failures += 1;
          failedConnectionIds.add(connection.id);
          this.#markConnectionDegraded(connection.id);
        }
      }
    }
    // A later successful node export calls bridge.touchConnection(). Preserve
    // the truthful aggregate state when any sibling node failed in this batch.
    for (const connectionId of failedConnectionIds) this.#markConnectionDegraded(connectionId);
    for (const [missionId, summary] of missionReports) {
      try {
        this.#audit.append({
          missionId,
          actor: { type: "system", id: "system:runtime-vault-projection" },
          action: summary.failures > 0
            ? "memory.vault_projection_degraded"
            : "memory.vault_projection_completed",
          resourceType: "memory_graph",
          resourceId: missionId,
          reason: summary.failures > 0
            ? "Canonical memory remained durable, but one or more optional Vault projections failed."
            : summary.skippedByPolicy > 0
              ? "Eligible canonical runtime memory was projected; policy-ineligible nodes remain durable and await operator confirmation or a scope change."
              : "Canonical runtime memory was projected into each eligible connected Vault.",
          details: {
            nodeIds: [...summary.nodeIds].sort(),
            connectionIds: [...summary.connectionIds].sort(),
            attempted: summary.attempted,
            synchronized: summary.synchronized,
            attentionRequired: summary.attentionRequired,
            skippedByPolicy: summary.skippedByPolicy,
            skippedByPolicyNodeIds: [...summary.skippedByPolicyNodeIds].sort(),
            failures: summary.failures,
          },
          occurredAt: this.#clock().toISOString(),
        });
      } catch {
        // The canonical memory and Vault sync-state rows remain truthful. An
        // audit-store failure must not turn optional projection into a second
        // authority capable of undoing an already committed terminal run.
      }
    }
    return {
      ...report,
      skippedByPolicyNodeIds: [...new Set(report.skippedByPolicyNodeIds)].sort(),
    };
  }

  purgeRevoked(nodeIds: readonly string[]): ConnectedVaultRevocationReport {
    const requestedNodeIds = [...new Set(nodeIds)].sort();
    const removedNodeIds = new Set<string>();
    let failures = 0;
    if (requestedNodeIds.length === 0) {
      return { requestedNodeIds, removedNodeIds: [], failures };
    }
    const connections = this.database.prepare(`
      SELECT id FROM vault_connections WHERE status = 'connected' ORDER BY id
    `).all() as Array<{ id: string }>;
    for (const connection of connections) {
      try {
        for (const nodeId of this.bridge.purgeRevokedNodeProjections(
          connection.id,
          requestedNodeIds,
        )) {
          removedNodeIds.add(nodeId);
        }
      } catch {
        failures += 1;
        this.#markConnectionDegraded(connection.id);
      }
    }
    return {
      requestedNodeIds,
      removedNodeIds: [...removedNodeIds].sort(),
      failures,
    };
  }

  #isPolicyExclusion(error: unknown): boolean {
    const message = error instanceof Error ? error.message.toLocaleLowerCase("en-US") : "";
    return message.includes("outside the vault connection")
      || message.includes("memory lifecycle")
      || message.includes("private operational provenance")
      || message.includes("synchronization is not permitted");
  }

  #missionIdsForNode(
    nodeId: string,
    scope: { readonly kind: string; readonly missionId?: string },
  ): readonly string[] {
    if (scope.kind === "mission" && scope.missionId) return [scope.missionId];
    const rows = this.database.prepare(`
      SELECT DISTINCT related.mission_id AS mission_id
      FROM memory_edges_safe edge
      JOIN memory_nodes related ON related.id = edge.source_node_id
      WHERE edge.target_node_id = ? AND related.mission_id IS NOT NULL
      UNION
      SELECT DISTINCT related.mission_id AS mission_id
      FROM memory_edges_safe edge
      JOIN memory_nodes related ON related.id = edge.target_node_id
      WHERE edge.source_node_id = ? AND related.mission_id IS NOT NULL
      ORDER BY mission_id
    `).all(nodeId, nodeId) as Array<{ mission_id: string }>;
    return rows.map(({ mission_id }) => mission_id);
  }

  #missionReport(
    reports: Map<string, {
      attempted: number;
      synchronized: number;
      attentionRequired: number;
      skippedByPolicy: number;
      skippedByPolicyNodeIds: Set<string>;
      failures: number;
      nodeIds: Set<string>;
      connectionIds: Set<string>;
    }>,
    missionId: string,
  ) {
    let report = reports.get(missionId);
    if (!report) {
      report = {
        attempted: 0,
        synchronized: 0,
        attentionRequired: 0,
        skippedByPolicy: 0,
        skippedByPolicyNodeIds: new Set(),
        failures: 0,
        nodeIds: new Set(),
        connectionIds: new Set(),
      };
      reports.set(missionId, report);
    }
    return report;
  }

  #markConnectionDegraded(connectionId: string): void {
    try {
      this.database.prepare(`
        UPDATE vault_connections SET status = 'degraded'
        WHERE id = ? AND status = 'connected'
      `).run(connectionId);
    } catch {
      // Failure isolation is intentional; readiness will still expose the
      // underlying filesystem/database fault on its next independent check.
    }
  }
}
