import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { scopeConflict } from "./errors";
import type { JsonValue, OperationalActor } from "./types";
import { canonicalJson, sanitizedJson, sha256 } from "./validation";

interface JourneyRow {
  readonly journey: "autonomous" | "guided";
  readonly mission_id?: string;
}

interface HashRow {
  readonly record_hash: string;
}

export interface AppendAuditInput {
  readonly missionId: string;
  readonly runId?: string;
  readonly actor: OperationalActor;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly reason: string;
  readonly details: JsonValue;
  readonly occurredAt: string;
}

/** Append-only, hash-linked audit writer for operational-truth transitions. */
export class AuditTrailWriter {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly idFactory: (prefix: string) => string = (prefix) => `${prefix}_${randomUUID()}`,
  ) {}

  append(input: AppendAuditInput): string {
    const mission = this.database.prepare("SELECT journey FROM missions WHERE id = ?")
      .get(input.missionId) as JourneyRow | undefined;
    if (!mission) throw scopeConflict("Audit mission does not exist");
    if (input.runId) {
      const run = this.database.prepare("SELECT journey, mission_id FROM runs WHERE id = ?")
        .get(input.runId) as JourneyRow | undefined;
      if (!run || run.mission_id !== input.missionId || run.journey !== mission.journey) {
        throw scopeConflict("Audit run does not belong to the mission and journey");
      }
    }
    const previous = this.database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
    ).get() as HashRow | undefined;
    const id = this.idFactory("audit");
    const details = sanitizedJson(input.details).value;
    const body: JsonValue = {
      id,
      missionId: input.missionId,
      runId: input.runId ?? null,
      journey: mission.journey,
      actorType: input.actor.type,
      actorId: input.actor.id,
      action: input.action,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      reason: input.reason,
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.occurredAt,
    };
    const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(body)}`);
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      input.missionId,
      input.runId ?? null,
      mission.journey,
      input.actor.type,
      input.actor.id,
      input.action,
      input.resourceType,
      input.resourceId,
      input.reason,
      canonicalJson(details),
      previous?.record_hash ?? null,
      recordHash,
      input.occurredAt,
    );
    return id;
  }
}
