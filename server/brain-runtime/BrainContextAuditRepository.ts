import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db/transaction";
import { canonicalJson, hashCanonical } from "../missions/canonical";
import {
  BRAIN_LIFECYCLE_HOOKS,
  type BrainAvailabilityPolicy,
  type BrainHookCoverage,
  type BrainHookCoverageRecord,
  type BrainLifecycleHook,
} from "./types";

type HookAuditStatus = BrainHookCoverageRecord["status"];

interface HookAuditDetails {
  readonly hook: BrainLifecycleHook;
  readonly status: HookAuditStatus;
  readonly contextPackId: string | null;
  readonly availabilityPolicy: BrainAvailabilityPolicy;
  readonly maximumSensitivity: "public" | "internal" | "private";
  readonly contextBudget: number;
  readonly limit: number;
  readonly allowGlobal: boolean;
  readonly retrievedCount: number;
  readonly noRelevantMemoryFound: boolean;
  readonly dependencyCode: string | null;
  readonly durationMs: number;
}

interface AuditRow {
  readonly id: string;
  readonly run_id: string | null;
  readonly details_json: string;
  readonly occurred_at: string;
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;

function assertId(value: string, label: string): void {
  if (!SAFE_ID.test(value)) throw new TypeError(`${label} is invalid`);
}

function parseDetails(source: string): HookAuditDetails | undefined {
  try {
    const value = JSON.parse(source) as Partial<HookAuditDetails>;
    if (
      !value || typeof value !== "object" ||
      !BRAIN_LIFECYCLE_HOOKS.includes(value.hook as BrainLifecycleHook) ||
      !["ready", "no_relevant_memory", "degraded", "blocked", "failed"].includes(String(value.status)) ||
      !["required", "degraded_allowed"].includes(String(value.availabilityPolicy)) ||
      typeof value.retrievedCount !== "number"
    ) return undefined;
    return value as HookAuditDetails;
  } catch {
    return undefined;
  }
}

/**
 * Append-only, hash-chained telemetry for mandatory Brain lifecycle hooks.
 * Raw retrieval queries and memory content are deliberately absent; the
 * canonical Context Pack owns the inspectable selected nodes.
 */
export class BrainContextAuditRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly now: () => Date = () => new Date(),
    private readonly createId: () => string = () => `audit-brain-hook-${randomUUID()}`,
  ) {}

  record(input: {
    readonly missionId: string;
    readonly runId?: string;
    readonly journey: "autonomous" | "guided";
    readonly actorId: string;
    readonly actorType: "operator" | "agent" | "worker" | "system";
    readonly details: HookAuditDetails;
  }): string {
    assertId(input.missionId, "Brain hook audit mission ID");
    if (input.runId) assertId(input.runId, "Brain hook audit run ID");
    assertId(input.actorId, "Brain hook audit actor ID");
    return inImmediateTransaction(this.database, () => {
      const mission = this.database.prepare(`
        SELECT journey FROM missions WHERE id = ?
      `).get(input.missionId) as { journey: "autonomous" | "guided" } | undefined;
      if (!mission || mission.journey !== input.journey) {
        throw new Error("Brain hook audit mission journey is not canonical");
      }
      if (input.runId) {
        const run = this.database.prepare(`
          SELECT mission_id, journey FROM runs WHERE id = ?
        `).get(input.runId) as {
          mission_id: string;
          journey: "autonomous" | "guided";
        } | undefined;
        if (!run || run.mission_id !== input.missionId || run.journey !== input.journey) {
          throw new Error("Brain hook audit run scope is not canonical");
        }
      }
      const previous = this.database.prepare(`
        SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1
      `).get() as { record_hash: string } | undefined;
      const id = this.createId();
      const occurredAt = this.now().toISOString();
      const reason = input.details.status === "degraded"
        ? "Lifecycle hook continued with an explicit empty degraded Context Pack"
        : input.details.status === "blocked"
          ? "Lifecycle hook failed closed because required Second Brain context was unavailable"
          : input.details.status === "failed"
            ? "Lifecycle hook failed closed because durable context or audit integrity could not be established"
            : input.details.status === "no_relevant_memory"
              ? "Lifecycle hook recorded that no relevant eligible memory was found"
              : "Lifecycle hook persisted bounded Second Brain context";
      const hashMaterial = {
        id,
        missionId: input.missionId,
        runId: input.runId ?? null,
        journey: input.journey,
        actorType: input.actorType,
        actorId: input.actorId,
        action: "brain.context_hook.invoked",
        resourceType: "brain_context_hook",
        resourceId: input.details.contextPackId ?? input.details.hook,
        reason,
        details: input.details,
        previousHash: previous?.record_hash ?? null,
        occurredAt,
      };
      const recordHash = hashCanonical(hashMaterial);
      this.database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json, previous_hash,
          record_hash, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'brain.context_hook.invoked',
          'brain_context_hook', ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        input.missionId,
        input.runId ?? null,
        input.journey,
        input.actorType,
        input.actorId,
        input.details.contextPackId ?? input.details.hook,
        reason,
        canonicalJson(input.details),
        previous?.record_hash ?? null,
        recordHash,
        occurredAt,
      );
      return id;
    });
  }

  coverage(input: { readonly missionId: string; readonly runId?: string }): BrainHookCoverage {
    assertId(input.missionId, "Brain hook coverage mission ID");
    if (input.runId) assertId(input.runId, "Brain hook coverage run ID");
    const rows = this.database.prepare(`
      SELECT id, run_id, details_json, occurred_at
      FROM audit_records
      WHERE action = 'brain.context_hook.invoked'
        AND mission_id = ?
        AND (${input.runId ? "(run_id = ? OR run_id IS NULL)" : "run_id IS NULL"})
      ORDER BY occurred_at, id
    `).all(...(input.runId ? [input.missionId, input.runId] : [input.missionId])) as AuditRow[];
    const invocations = rows.flatMap((row): BrainHookCoverageRecord[] => {
      const details = parseDetails(row.details_json);
      if (!details) return [];
      // Intake occurs before a run exists, but remains part of every later
      // run's lifecycle coverage for that mission. Other mission-wide rows do
      // not silently satisfy a run-scoped hook.
      if (input.runId && row.run_id === null && details.hook !== "intake") return [];
      return [{
        auditRecordId: row.id,
        hook: details.hook,
        status: details.status,
        contextPackId: details.contextPackId,
        availabilityPolicy: details.availabilityPolicy,
        retrievedCount: details.retrievedCount,
        occurredAt: row.occurred_at,
      }];
    });
    const covered = new Set(invocations.map((invocation) => invocation.hook));
    return {
      missionId: input.missionId,
      ...(input.runId ? { runId: input.runId } : {}),
      coveredHooks: BRAIN_LIFECYCLE_HOOKS.filter((hook) => covered.has(hook)),
      missingHooks: BRAIN_LIFECYCLE_HOOKS.filter((hook) => !covered.has(hook)),
      invocations,
    };
  }
}

export type { HookAuditDetails };
