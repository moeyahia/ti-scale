import { createHash } from "node:crypto";
import { createReadStream, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { resolve } from "node:path";
import type { SqliteDatabase } from "../db";
import { createDatabaseConnection, inImmediateTransaction } from "../db";
import {
  findLessonTargetSpecificIdentifiers,
  findReusableContentIdentifiers,
  isReusableLessonSafe,
  validateAndNormalizeLesson,
} from "../learning/AttackLesson";
import { AttackChainLearningService } from "../learning";
import { MigrationMetadataRepository } from "./MigrationMetadataRepository";
import {
  containsHardSecret,
  redactLegacyText,
  safeJson,
  sha256Text,
} from "./SecretSafety";
import type {
  LegacySource,
  SourceMigrationResult,
} from "./types";

interface ImportStats {
  imported: number;
  deduplicated: number;
  quarantined: number;
  skipped: number;
  targetCounts: Record<string, number>;
}

type RecordValue = Record<string, unknown>;

function isRecord(value: unknown): value is RecordValue {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function stableId(prefix: string, ...parts: unknown[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(typeof part === "string" ? part : JSON.stringify(part));
  return `${prefix}_legacy_${hash.digest("hex").slice(0, 40)}`;
}

function asText(value: unknown, fallback = ""): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function asIso(value: unknown, fallback: string): string {
  if (typeof value === "number" && Number.isFinite(value)) {
    const milliseconds = value < 100_000_000_000 ? value * 1_000 : value;
    const parsed = new Date(milliseconds);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  if (typeof value === "string") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return fallback;
}

function jsonHash(value: unknown): string {
  return sha256Text(JSON.stringify(value));
}

function legacyRunStatus(value: unknown): "blocked" | "completed" | "failed" | "cancelled" {
  switch (String(value ?? "").toLowerCase()) {
    case "completed":
    case "complete":
    case "done":
      return "completed";
    case "cancelled":
    case "canceled":
      return "cancelled";
    case "failed":
    case "crashed":
    case "timed_out":
      return "failed";
    default:
      // Never resume an unverifiable legacy in-flight action automatically.
      return "blocked";
  }
}

function legacyMissionStatus(value: unknown): "paused" | "completed" | "failed" | "cancelled" {
  const status = legacyRunStatus(value);
  return status === "blocked" ? "paused" : status;
}

function stepStatus(value: unknown): string {
  switch (String(value ?? "").toLowerCase()) {
    case "completed": case "done": return "completed";
    case "failed": case "crashed": case "timed_out": return "failed";
    case "cancelled": case "canceled": return "cancelled";
    case "skipped": return "skipped";
    case "blocked": return "blocked";
    default: return "pending";
  }
}

function normalizeRole(value: unknown): "operator" | "assistant" | "system" | "tool" {
  switch (String(value ?? "").toLowerCase()) {
    case "user": case "operator": return "operator";
    case "assistant": case "agent": case "model": return "assistant";
    case "tool": case "function": return "tool";
    default: return "system";
  }
}

function safeSeverity(value: unknown): "trace" | "debug" | "info" | "warn" | "error" | "fatal" {
  switch (String(value ?? "").toLowerCase()) {
    case "trace": return "trace";
    case "debug": return "debug";
    case "warn": case "warning": return "warn";
    case "error": return "error";
    case "fatal": case "critical": return "fatal";
    default: return "info";
  }
}

function targetIncrement(stats: ImportStats, target: string): void {
  stats.targetCounts[target] = (stats.targetCounts[target] ?? 0) + 1;
}

/** Conservative translator from legacy stores into current canonical tables. */
export class LegacyImporter {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly metadata: MigrationMetadataRepository,
    private readonly migrationId: string,
    private readonly sourceId: string,
    private readonly source: LegacySource,
    private readonly clock: () => Date = () => new Date(),
    private readonly readPath: string = source.absolutePath,
  ) {}

  async import(): Promise<SourceMigrationResult> {
    const stats: ImportStats = { imported: 0, deduplicated: 0, quarantined: 0, skipped: 0, targetCounts: {} };
    switch (this.source.type) {
      case "run_json": await this.importRunJson(stats); break;
      case "session_json": await this.importSessionJson(stats); break;
      case "event_jsonl": await this.importEventJsonl(stats); break;
      case "raw_llm_jsonl": await this.importRawLlmJsonl(stats); break;
      case "provider_session_json": await this.importSessionJson(stats); break;
      case "provider_session_jsonl": await this.importRawLlmJsonl(stats); break;
      case "provider_log": await this.importDashboardLog(stats); break;
      case "conversation_markdown":
        // Markdown history is intentionally canonical only in the bounded
        // attack-knowledge pipeline; legacy target-centric projection skips it.
        stats.skipped += 1;
        break;
      case "dashboard_log": await this.importDashboardLog(stats); break;
      case "memory_json": await this.importMemoryJson(stats); break;
      case "training_json": await this.importTrainingJson(stats); break;
      case "artifact": await this.importArtifact(stats); break;
      case "kanban_sqlite": await this.importKanban(stats); break;
      case "conversation_state_sqlite": await this.importConversationState(stats); break;
      case "engagement_manifest":
        throw new Error("Engagement manifests must be imported by LegacyEngagementImporter");
    }
    return { source: this.source, ...stats };
  }

  private now(): string { return this.clock().toISOString(); }
  private sourceIdentity(): string { return sha256Text(`${this.source.type}\0${this.source.absolutePath}`); }

  private processItem(
    stats: ImportStats,
    itemKey: string,
    value: unknown,
    insert: () => { targetTable?: string; targetId?: string } | undefined,
  ): void {
    const itemHash = jsonHash(value);
    const previous = this.metadata.previousItem(this.sourceIdentity(), this.source.sha256, itemKey, itemHash);
    if (previous) {
      stats.deduplicated += 1;
      // Reconciliation targets describe every canonical item matched by this
      // pass, including rows imported before an interrupted run was resumed.
      if (previous.targetTable) targetIncrement(stats, previous.targetTable);
      return;
    }
    try {
      const result = inImmediateTransaction(this.database, () => {
        const target = insert();
        this.metadata.recordItem({
          migrationId: this.migrationId,
          sourceId: this.sourceId,
          sourceIdentity: this.sourceIdentity(),
          sourceSha256: this.source.sha256,
          itemKey,
          itemHash,
          status: target ? "imported" : "skipped",
          ...target,
        });
        return target;
      });
      if (result) {
        stats.imported += 1;
        if (result.targetTable) targetIncrement(stats, result.targetTable);
      } else stats.skipped += 1;
    } catch (error) {
      this.quarantine(stats, itemKey, itemHash, "canonical_insert_failed", error, value);
    }
  }

  private quarantine(
    stats: ImportStats,
    itemKey: string,
    itemHash: string | undefined,
    category: string,
    error: unknown,
    excerpt?: unknown,
  ): void {
    if (itemHash && this.metadata.previousItem(this.sourceIdentity(), this.source.sha256, itemKey, itemHash)) {
      stats.deduplicated += 1;
      return;
    }
    const reason = redactLegacyText(error instanceof Error ? error.message : String(error), 1_000);
    inImmediateTransaction(this.database, () => {
      this.metadata.quarantine(this.migrationId, {
        sourceSha256: this.source.sha256,
        sourcePath: this.source.absolutePath,
        itemKey,
        ...(itemHash ? { itemHash } : {}),
        category,
        reason,
        ...(excerpt === undefined ? {} : { redactedExcerpt: redactLegacyText(excerpt, 800) }),
      });
      this.metadata.recordItem({
        migrationId: this.migrationId,
        sourceId: this.sourceId,
        sourceIdentity: this.sourceIdentity(),
        sourceSha256: this.source.sha256,
        itemKey,
        itemHash: itemHash ?? sha256Text(`${category}\0${reason}`),
        status: "quarantined",
        errorCategory: category,
      });
    });
    stats.quarantined += 1;
  }

  private readJson(): unknown {
    return JSON.parse(readFileSync(this.readPath, "utf8")) as unknown;
  }

  private createLegacyMission(input: {
    key: string;
    title: string;
    objective: string;
    status?: unknown;
    engagement?: string;
    createdAt?: unknown;
    updatedAt?: unknown;
    provenance?: unknown;
  }): string {
    const missionId = stableId("mission", this.sourceIdentity(), input.key);
    const now = this.now();
    const createdAt = asIso(input.createdAt, this.source.modifiedAt || now);
    const updatedAt = asIso(input.updatedAt, createdAt);
    this.database.prepare(`
      INSERT OR IGNORE INTO missions (
        id, name, objective, journey, status, authorization_status, engagement_id,
        scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
        created_by, version, created_at, updated_at, control_plane
      ) VALUES (?, ?, ?, 'guided', ?, 'unverified', ?, ?, '[]', ?, ?, 'import:legacy', 1, ?, ?, 'legacy')
    `).run(
      missionId,
      redactLegacyText(input.title || "Legacy mission", 240),
      redactLegacyText(input.objective || "Legacy objective unavailable", 8_000),
      legacyMissionStatus(input.status),
      input.engagement ? redactLegacyText(input.engagement, 240) : null,
      safeJson({ legacy: true, executionAuthorized: false, provenance: input.provenance ?? {} }),
      safeJson({ source: "legacy_import", preserveUntilReviewed: true }),
      safeJson({ reusableRetrieval: false }),
      createdAt,
      updatedAt,
    );
    return missionId;
  }

  private createLegacyRun(input: {
    key: string;
    missionId: string;
    status?: unknown;
    reason?: string;
    createdAt?: unknown;
    updatedAt?: unknown;
    endedAt?: unknown;
    provider?: string;
  }): string {
    const runId = stableId("run", this.sourceIdentity(), input.key);
    const now = this.now();
    const createdAt = asIso(input.createdAt, this.source.modifiedAt || now);
    const updatedAt = asIso(input.updatedAt, createdAt);
    const status = legacyRunStatus(input.status);
    this.database.prepare(`
      INSERT OR IGNORE INTO runs (
        id, mission_id, journey, status, progress, status_reason, next_action_summary,
        budget_json, budget_usage_json, retry_count, replan_count,
        started_at, ended_at, created_at, updated_at, version, control_plane
      ) VALUES (?, ?, 'guided', ?, ?, ?, NULL, '{}', '{}', 0, 0, ?, ?, ?, ?, 1, 'legacy')
    `).run(
      runId,
      input.missionId,
      status,
      status === "completed" ? 1 : 0,
      redactLegacyText(input.reason || (status === "blocked" ? "Legacy nonterminal run requires explicit review" : "Legacy import"), 1_000),
      createdAt,
      input.endedAt ? asIso(input.endedAt, updatedAt) : (status === "blocked" ? null : updatedAt),
      createdAt,
      updatedAt,
    );
    return runId;
  }

  private async importRunJson(stats: ImportStats): Promise<void> {
    let parsed: unknown;
    try { parsed = this.readJson(); }
    catch (error) { this.quarantine(stats, "document", undefined, "malformed_json", error); return; }
    if (!isRecord(parsed) || !isRecord(parsed.run)) {
      this.quarantine(stats, "document", jsonHash(parsed), "invalid_run_document", "run object is required", parsed);
      return;
    }
    const run = parsed.run;
    const key = asText(run.id, this.source.relativePath);
    this.processItem(stats, `run:${key}`, parsed, () => {
      const missionId = this.createLegacyMission({
        key,
        title: asText(run.objective, `Legacy run ${key}`).slice(0, 180),
        objective: asText(run.objective, "Legacy objective unavailable"),
        status: run.status,
        engagement: asText(run.engagement) || undefined,
        createdAt: run.createdAt,
        updatedAt: run.updatedAt,
        provenance: { sourceSha256: this.source.sha256, legacyRunId: key },
      });
      const runId = this.createLegacyRun({
        key,
        missionId,
        status: run.status,
        reason: asText(run.endReason),
        createdAt: run.createdAt,
        updatedAt: run.updatedAt,
        endedAt: run.endedAt,
        provider: asText(run.providerKind),
      });
      const steps = Array.isArray(parsed.steps) ? parsed.steps.filter(isRecord) : [];
      if (steps.length) {
        const planId = stableId("plan", runId, "legacy-plan");
        this.database.prepare(`
          INSERT OR IGNORE INTO plans (
            id, run_id, version, status, strategy_summary, rationale_summary,
            plan_hash, created_by, created_at, activated_at
          ) VALUES (?, ?, 1, 'completed', ?, ?, ?, 'import:legacy', ?, ?)
        `).run(
          planId,
          runId,
          "Imported legacy plan; not an authorization contract",
          "Preserved for historical review only",
          jsonHash(steps),
          asIso(run.createdAt, this.source.modifiedAt),
          asIso(run.createdAt, this.source.modifiedAt),
        );
        const insertStep = this.database.prepare(`
          INSERT OR IGNORE INTO plan_steps (
            id, plan_id, run_id, ordinal, phase, title, objective, status,
            success_criteria_json, dependencies_json, action_class, risk_class,
            assigned_agent_id, started_at, ended_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'legacy', ?, ?, ?, ?, ?, 'legacy_observation', ?, NULL, ?, ?, ?, ?)
        `);
        steps.forEach((step, index) => {
          insertStep.run(
            stableId("step", runId, asText(step.id, String(index))),
            planId,
            runId,
            Number.isInteger(step.index) ? step.index as number : index,
            redactLegacyText(step.title || `Legacy step ${index + 1}`, 240),
            redactLegacyText(step.purpose || step.title || "Legacy step", 4_000),
            stepStatus(step.status),
            safeJson(asStringArray(step.successCriteria).length ? asStringArray(step.successCriteria) : [asText(step.successCriteria)].filter(Boolean)),
            safeJson(asStringArray(step.dependencies)),
            asText(step.riskLevel, "unknown"),
            step.startedAt ? asIso(step.startedAt, this.source.modifiedAt) : null,
            step.endedAt ? asIso(step.endedAt, this.source.modifiedAt) : null,
            asIso(step.createdAt, this.source.modifiedAt),
            asIso(step.updatedAt, this.source.modifiedAt),
          );
        });
        this.database.prepare("UPDATE runs SET current_plan_id = ? WHERE id = ?").run(planId, runId);
      }
      const evidence = Array.isArray(parsed.evidence) ? parsed.evidence.filter(isRecord) : [];
      const insertEvidence = this.database.prepare(`
        INSERT OR IGNORE INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity, verification_state,
          summary, extracted_text, created_by, created_at
        ) VALUES (?, ?, ?, 'legacy_runtime', ?, NULL, ?, ?, ?, 0.5, 'restricted',
          'unverified', ?, ?, 'import:legacy', ?)
      `);
      for (const [index, item] of evidence.entries()) {
        const rawContent = asText(item.content);
        const evidenceId = stableId("evidence", runId, asText(item.id, String(index)));
        const acquiredAt = asIso(item.createdAt, this.source.modifiedAt);
        insertEvidence.run(
          evidenceId,
          missionId,
          runId,
          acquiredAt,
          asText(item.kind, "legacy"),
          jsonHash(item),
          safeJson({ sourceSha256: this.source.sha256, legacyId: item.id ?? null }),
          redactLegacyText(item.label || `Legacy evidence ${index + 1}`, 500),
          rawContent ? redactLegacyText(rawContent, 32_768) : null,
          acquiredAt,
        );
        this.database.prepare(`
          INSERT OR IGNORE INTO evidence_chain_events (
            id, evidence_id, event_type, actor, details_json, occurred_at
          ) VALUES (?, ?, 'legacy_imported', 'import:legacy', ?, ?)
        `).run(
          stableId("evidence_chain", evidenceId, "legacy-imported"),
          evidenceId,
          safeJson({ migrationId: this.migrationId, sourceId: this.sourceId }),
          acquiredAt,
        );
      }
      return { targetTable: "runs", targetId: runId };
    });
  }

  private sessionMessages(parsed: unknown): { session: RecordValue; messages: RecordValue[] } | undefined {
    if (Array.isArray(parsed)) return { session: {}, messages: parsed.filter(isRecord) };
    if (!isRecord(parsed)) return undefined;
    const messages = Array.isArray(parsed.messages)
      ? parsed.messages.filter(isRecord)
      : Array.isArray(parsed.history) ? parsed.history.filter(isRecord) : [];
    const { messages: _messages, history: _history, ...session } = parsed;
    return { session, messages };
  }

  private async importSessionJson(stats: ImportStats): Promise<void> {
    let parsed: unknown;
    try { parsed = this.readJson(); }
    catch (error) { this.quarantine(stats, "document", undefined, "malformed_json", error); return; }
    const normalized = this.sessionMessages(parsed);
    if (!normalized) {
      this.quarantine(stats, "document", jsonHash(parsed), "invalid_session_document", "session must be an object or message array", parsed);
      return;
    }
    const sessionKey = asText(normalized.session.id, this.source.relativePath);
    const conversationId = stableId("conversation", this.sourceIdentity(), sessionKey);
    this.processItem(stats, `session:${sessionKey}`, normalized.session, () => {
      const createdAt = asIso(normalized.session.createdAt ?? normalized.session.started_at, this.source.modifiedAt);
      this.database.prepare(`
        INSERT OR IGNORE INTO conversations (
          id, conversation_type, created_at, updated_at
        ) VALUES (?, 'global', ?, ?)
      `).run(conversationId, createdAt, asIso(normalized.session.updatedAt ?? normalized.session.ended_at, createdAt));
      return { targetTable: "conversations", targetId: conversationId };
    });
    normalized.messages.forEach((message, index) => this.importMessage(stats, conversationId, sessionKey, message, index));
  }

  private importMessage(stats: ImportStats, conversationId: string, sessionKey: string, message: RecordValue, index: number): void {
    const key = `message:${sessionKey}:${asText(message.id, String(index))}`;
    this.processItem(stats, key, message, () => {
      const bodySource = message.content ?? message.body ?? message.text ?? message.message ?? "";
      const body = redactLegacyText(bodySource, 64_000);
      if (!body.trim()) return undefined;
      const messageId = stableId("message", this.sourceIdentity(), key);
      const createdAt = asIso(message.timestamp ?? message.createdAt ?? message.created_at, this.source.modifiedAt);
      this.database.prepare(`
        INSERT OR IGNORE INTO messages (
          id, conversation_id, role, body, structured_content_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        messageId,
        conversationId,
        normalizeRole(message.role),
        body,
        safeJson({ legacy: true, sourceSha256: this.source.sha256, finishReason: message.finish_reason ?? null }),
        createdAt,
      );
      return { targetTable: "messages", targetId: messageId };
    });
  }

  private async forEachJsonLine(
    stats: ImportStats,
    handler: (record: unknown, line: number) => void,
  ): Promise<void> {
    const input = createReadStream(this.readPath, { encoding: "utf8" });
    const reader = createInterface({ input, crlfDelay: Infinity });
    let lineNumber = 0;
    for await (const line of reader) {
      lineNumber += 1;
      const text = line.trim();
      if (!text) continue;
      try { handler(JSON.parse(text) as unknown, lineNumber); }
      catch (error) { this.quarantine(stats, `line:${lineNumber}`, sha256Text(text), "malformed_jsonl", error, text); }
    }
  }

  private async importEventJsonl(stats: ImportStats): Promise<void> {
    await this.forEachJsonLine(stats, (record, line) => {
      if (!isRecord(record)) throw new Error("event line must be an object");
      const itemKey = `event:${asText(record.id, String(line))}`;
      this.processItem(stats, itemKey, record, () => {
        const logId = stableId("log", this.sourceIdentity(), itemKey);
        const occurredAt = asIso(record.timestamp ?? record.occurred_at, this.source.modifiedAt);
        this.database.prepare(`
          INSERT OR IGNORE INTO structured_logs (
            id, severity, domain, message, attributes_json, sensitivity, occurred_at
          ) VALUES (?, ?, 'legacy_event', ?, ?, 'restricted', ?)
        `).run(
          logId,
          String(record.type ?? "").includes("failed") ? "error" : "info",
          redactLegacyText(record.summary ?? record.type ?? "Legacy event", 2_000),
          safeJson({
            eventType: record.type ?? "legacy_event",
            sourceSha256: this.source.sha256,
            legacyRunId: record.agentRunId ?? record.run_id ?? null,
            legacySessionId: record.sessionId ?? record.session_id ?? null,
            data: record.data ?? record.payload ?? {},
          }),
          occurredAt,
        );
        const eventId = this.insertCanonicalLegacyEvent(record, itemKey, occurredAt);
        return eventId
          ? { targetTable: "events", targetId: eventId }
          : { targetTable: "structured_logs", targetId: logId };
      });
    });
  }

  private insertCanonicalLegacyEvent(record: RecordValue, itemKey: string, occurredAt: string): string | undefined {
    const legacyRunId = asText(record.agentRunId ?? record.run_id);
    if (!legacyRunId || !this.source.root || this.source.root === this.source.absolutePath) return undefined;
    const legacyRunPath = resolve(this.source.root, "runtime", "runs", `${legacyRunId}.json`);
    const runSourceIdentity = sha256Text(`run_json\0${legacyRunPath}`);
    const runId = stableId("run", runSourceIdentity, legacyRunId);
    const run = this.database.prepare("SELECT mission_id, journey FROM runs WHERE id = ?").get(runId) as {
      mission_id: string;
      journey: "autonomous" | "guided";
    } | undefined;
    if (!run) return undefined;
    const allocated = this.database.prepare(`
      INSERT INTO run_event_sequences (run_id, last_sequence)
      VALUES (?, COALESCE((SELECT MAX(sequence) + 1 FROM events WHERE run_id = ?), 1))
      ON CONFLICT(run_id) DO UPDATE SET last_sequence = last_sequence + 1
      RETURNING last_sequence
    `).get(runId, runId) as { last_sequence: number } | undefined;
    if (!allocated) throw new Error("unable to allocate legacy event sequence");
    const eventId = stableId("event", this.sourceIdentity(), itemKey);
    const eventType = redactLegacyText(asText(record.type ?? record.event_type, "legacy_event"), 200);
    const summary = redactLegacyText(record.summary ?? eventType.replaceAll("_", " "), 2_000);
    const payload = {
      sourceSha256: this.source.sha256,
      legacyEventId: record.id ?? null,
      legacySessionId: record.sessionId ?? record.session_id ?? null,
      data: record.data ?? record.payload ?? {},
    };
    const inserted = this.database.prepare(`
      INSERT OR IGNORE INTO events (
        id, mission_id, run_id, sequence, event_type, occurred_at,
        actor_type, actor_id, summary, payload_json, schema_version, journey,
        sensitivity, redaction_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'system', 'import:legacy', ?, ?, 1, ?,
        'restricted', ?, ?)
    `).run(
      eventId,
      run.mission_id,
      runId,
      allocated.last_sequence,
      eventType,
      occurredAt,
      summary,
      safeJson(payload),
      run.journey,
      safeJson({ imported: true, secrets: "redacted" }),
      this.now(),
    );
    if (inserted.changes > 0) {
      this.database.prepare(`
        INSERT OR IGNORE INTO event_outbox (
          id, event_id, topic, payload_json, status, attempt_count,
          available_at, delivered_at, created_at
        ) VALUES (?, ?, 'run.events', ?, 'delivered', 0, ?, ?, ?)
      `).run(
        `outbox:${eventId}`,
        eventId,
        safeJson({ eventId, runId, journey: run.journey, imported: true }),
        occurredAt,
        this.now(),
        this.now(),
      );
    }
    return eventId;
  }

  private async importRawLlmJsonl(stats: ImportStats): Promise<void> {
    const conversationId = stableId("conversation", this.sourceIdentity(), "raw-llm");
    this.processItem(stats, "conversation:raw-llm", { path: this.source.relativePath }, () => {
      this.database.prepare(`
        INSERT OR IGNORE INTO conversations (id, conversation_type, created_at, updated_at)
        VALUES (?, 'system', ?, ?)
      `).run(conversationId, this.source.modifiedAt, this.source.modifiedAt);
      return { targetTable: "conversations", targetId: conversationId };
    });
    await this.forEachJsonLine(stats, (record, line) => {
      if (!isRecord(record)) throw new Error("raw provider line must be an object");
      const itemKey = `provider-line:${line}`;
      this.processItem(stats, itemKey, record, () => {
        const bodySource = record.content ?? record.text ?? record.output ?? record.message ?? record.response;
        const recordKind = asText(record.type ?? record.kind ?? record.event_type).toLowerCase();
        const body = /(?:reasoning|thinking|chain[_ -]?of[_ -]?thought)/u.test(recordKind)
          ? "[Legacy private reasoning payload omitted]"
          : redactLegacyText(bodySource ?? "[Legacy provider metadata record; no displayable message body]", 64_000);
        const messageId = stableId("message", this.sourceIdentity(), itemKey);
        const timestamp = asIso(record.timestamp ?? record.ts ?? record.created_at, this.source.modifiedAt);
        this.database.prepare(`
          INSERT OR IGNORE INTO messages (
            id, conversation_id, role, body, structured_content_json, created_at
          ) VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          messageId,
          conversationId,
          normalizeRole(record.role ?? record.direction),
          body,
          safeJson({ legacy: true, sourceSha256: this.source.sha256, line }),
          timestamp,
        );
        const provider = asText(record.provider);
        if (provider) {
          this.database.prepare(`
            INSERT OR IGNORE INTO provider_turns (
              id, conversation_id, message_id, provider, model, status,
              input_tokens, output_tokens, estimated_cost, latency_ms,
              error_category, started_at, ended_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            stableId("provider_turn", this.sourceIdentity(), itemKey),
            conversationId,
            messageId,
            redactLegacyText(provider, 100),
            asText(record.model) ? redactLegacyText(record.model, 100) : null,
            record.error ? "failed" : "completed",
            Number.isSafeInteger(record.input_tokens) ? record.input_tokens : null,
            Number.isSafeInteger(record.output_tokens) ? record.output_tokens : null,
            typeof record.estimated_cost === "number" && record.estimated_cost >= 0 ? record.estimated_cost : null,
            Number.isSafeInteger(record.latency_ms) && (record.latency_ms as number) >= 0 ? record.latency_ms : null,
            record.error ? "legacy_provider_error" : null,
            timestamp,
            timestamp,
          );
        }
        return { targetTable: "messages", targetId: messageId };
      });
    });
  }

  private async importDashboardLog(stats: ImportStats): Promise<void> {
    const reader = createInterface({ input: createReadStream(this.readPath, { encoding: "utf8" }), crlfDelay: Infinity });
    let line = 0;
    const batch: Array<{ line: number; raw: string }> = [];
    const flush = (): void => {
      if (batch.length === 0) return;
      const pending = batch.splice(0, batch.length);
      inImmediateTransaction(this.database, () => {
        for (const item of pending) this.importDashboardLogLine(stats, item.line, item.raw);
      });
    };
    for await (const raw of reader) {
      line += 1;
      if (!raw.trim()) continue;
      batch.push({ line, raw });
      if (batch.length >= 1_000) flush();
    }
    flush();
  }

  private importDashboardLogLine(stats: ImportStats, line: number, raw: string): void {
    this.processItem(stats, `log-line:${line}`, raw, () => {
      const id = stableId("log", this.sourceIdentity(), line);
      let parsed: RecordValue | undefined;
      try { const value = JSON.parse(raw) as unknown; if (isRecord(value)) parsed = value; } catch {}
      this.database.prepare(`
        INSERT OR IGNORE INTO structured_logs (
          id, severity, domain, message, attributes_json, sensitivity, occurred_at
        ) VALUES (?, ?, 'legacy_dashboard', ?, ?, 'restricted', ?)
      `).run(
        id,
        safeSeverity(parsed?.level ?? parsed?.severity),
        redactLegacyText(parsed?.message ?? raw, 8_000),
        safeJson({ sourceSha256: this.source.sha256, line }),
        asIso(parsed?.timestamp ?? parsed?.ts, this.source.modifiedAt),
      );
      return { targetTable: "structured_logs", targetId: id };
    });
  }

  private async importMemoryJson(stats: ImportStats): Promise<void> {
    let parsed: unknown;
    try { parsed = this.readJson(); }
    catch (error) { this.quarantine(stats, "document", undefined, "malformed_json", error); return; }
    if (!Array.isArray(parsed)) {
      this.quarantine(stats, "document", jsonHash(parsed), "invalid_memory_document", "memory document must be an array", parsed);
      return;
    }
    parsed.forEach((raw, index) => {
      if (!isRecord(raw)) {
        this.quarantine(stats, `memory:${index}`, jsonHash(raw), "invalid_memory_item", "memory item must be an object", raw);
        return;
      }
      const content = asText(raw.content ?? raw.summary ?? raw.body);
      const key = `memory:${asText(raw.id, String(index))}`;
      const targetIdentifiers = content ? findReusableContentIdentifiers(content) : [];
      if (!content || containsHardSecret(content) || targetIdentifiers.length) {
        this.quarantine(
          stats,
          key,
          jsonHash(raw),
          "unsafe_memory",
          targetIdentifiers.length
            ? `memory contains target-specific identifier(s): ${targetIdentifiers.join(", ")}`
            : "memory is empty or contains non-reusable secret material",
          raw,
        );
        return;
      }
      this.processItem(stats, key, raw, () => {
        const type = asText(raw.type).toLowerCase();
        // Uncorrelated target facts never become globally reusable memory.
        if (["engagement_fact", "finding", "hypothesis"].includes(type)) {
          throw new Error("target-specific memory requires mission correlation review");
        }
        const id = stableId("memory_candidate", this.sourceIdentity(), key);
        const nodeType = type === "user_preference" ? "preference" : "procedure";
        this.database.prepare(`
          INSERT OR IGNORE INTO memory_candidates (
            id, candidate_type, title, summary, body, proposed_scope,
            sensitivity, confidence, source_json, status, proposed_by, created_at
          ) VALUES (?, ?, ?, ?, ?, 'global', 'private', ?, ?, 'pending', 'import:legacy', ?)
        `).run(
          id,
          nodeType,
          redactLegacyText(asText(raw.title, content.slice(0, 100)), 200),
          redactLegacyText(content, 1_000),
          redactLegacyText(content, 32_768),
          typeof raw.confidence === "number" ? Math.max(0, Math.min(1, raw.confidence)) : 0.4,
          safeJson({ kind: "legacy_memory", sourceSha256: this.source.sha256, legacyId: raw.id ?? null }),
          asIso(raw.timestamp, this.source.modifiedAt),
        );
        return { targetTable: "memory_candidates", targetId: id };
      });
    });
  }

  private async importTrainingJson(stats: ImportStats): Promise<void> {
    let parsed: unknown;
    try { parsed = this.readJson(); }
    catch (error) { this.quarantine(stats, "document", undefined, "malformed_json", error); return; }
    if (!Array.isArray(parsed)) {
      this.quarantine(stats, "document", jsonHash(parsed), "invalid_training_document", "training document must be an array", parsed);
      return;
    }
    parsed.forEach((raw, index) => {
      const key = `lesson:${isRecord(raw) ? asText(raw.id, String(index)) : index}`;
      const validation = validateAndNormalizeLesson(raw);
      if (!validation.ok) {
        const errors = "errors" in validation && Array.isArray(validation.errors)
          ? validation.errors
          : ["legacy lesson validation failed"];
        this.quarantine(stats, key, jsonHash(raw), "invalid_lesson", errors.join("; "), raw);
        return;
      }
      if (!validation.lesson) {
        this.quarantine(stats, key, jsonHash(raw), "invalid_lesson", "validated lesson body is missing", raw);
        return;
      }
      const identifiers = findLessonTargetSpecificIdentifiers(validation.lesson);
      if (!isReusableLessonSafe(validation.lesson) || identifiers.length) {
        this.quarantine(stats, key, jsonHash(raw), "unsafe_or_target_specific_lesson", identifiers.join(", ") || "secret policy rejected lesson", raw);
        return;
      }
      const lesson = validation.lesson;
      this.processItem(stats, key, raw, () => {
        const id = stableId("lesson", this.sourceIdentity(), key);
        const statement = [lesson.techniqueName, lesson.summary].filter(Boolean).join(": ");
        this.database.prepare(`
          INSERT OR IGNORE INTO lessons (
            id, statement, lesson_type, applicability_scope, failure_category,
            retry_conditions, confidence, expected_benefit, risk, status,
            authoring_agent_id, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?, ?)
        `).run(
          id,
          redactLegacyText(statement, 8_000),
          lesson.kind,
          lesson.scope,
          lesson.kind === "failed_attempt" ? "legacy_failed_attempt" : null,
          lesson.conditions ? redactLegacyText(lesson.conditions, 2_000) : null,
          Math.max(0, Math.min(1, lesson.confidence)),
          redactLegacyText(lesson.reuseGuidance || lesson.outcome || "Requires operator review", 4_000),
          redactLegacyText(lesson.antiReuseWarnings.join("; ") || "Imported lesson is unverified", 4_000),
          lesson.agentId ? redactLegacyText(lesson.agentId, 100) : null,
          asIso((raw as RecordValue).createdAt, this.source.modifiedAt),
          asIso((raw as RecordValue).createdAt, this.source.modifiedAt),
        );
        if (lesson.kind === "attack_chain") {
          new AttackChainLearningService(this.database, { clock: this.clock }).retainCandidateDetails(id, {
            title: lesson.title,
            techniqueName: lesson.techniqueName,
            techniqueCategory: lesson.techniqueCategory,
            summary: lesson.summary,
            prerequisites: lesson.prerequisites,
            observedSignals: lesson.observedSignals,
            orderedSteps: lesson.stepsThatWorked,
            tools: lesson.toolsUsed,
            publicReferences: lesson.references,
            validationCheckpoints: lesson.verificationMethod ? [lesson.verificationMethod] : [],
            failureRecovery: lesson.failedAttempts,
            antiReuseWarnings: lesson.antiReuseWarnings,
            expectedOutcome: lesson.outcome,
            reuseGuidance: lesson.reuseGuidance,
            confidence: lesson.confidence,
            scope: lesson.scope,
            agentId: lesson.agentId,
            sources: [{
              sourceType: "legacy_training",
              sourceId: this.source.sha256,
              sourceHash: this.source.sha256,
            }],
          }, "import:legacy");
        }
        return { targetTable: "lessons", targetId: id };
      });
    });
  }

  private async importArtifact(stats: ImportStats): Promise<void> {
    const key = `artifact:${this.source.relativePath}`;
    this.processItem(stats, key, { sha256: this.source.sha256, size: this.source.byteSize }, () => {
      const missionId = this.createLegacyMission({
        key: "unassociated-artifacts",
        title: "Legacy unassociated artifacts",
        objective: "Preserve legacy artifact metadata for operator review; this record grants no execution authorization.",
        status: "completed",
        provenance: { sourceSha256: this.source.sha256 },
      });
      const id = stableId("artifact", this.sourceIdentity(), this.source.relativePath);
      this.database.prepare(`
        INSERT OR IGNORE INTO artifacts (
          id, mission_id, journey, artifact_type, storage_uri, content_hash, byte_size,
          sensitivity, metadata_json, created_at
        ) VALUES (?, ?, 'guided', 'legacy_file', ?, ?, ?, 'restricted', ?, ?)
      `).run(
        id,
        missionId,
        `legacy-migration-source://${this.sourceId}`,
        this.source.sha256,
        this.source.byteSize,
        safeJson({ originalName: this.source.relativePath.split("/").at(-1), sourceSha256: this.source.sha256 }),
        this.source.modifiedAt,
      );
      return { targetTable: "artifacts", targetId: id };
    });
  }

  private async importKanban(stats: ImportStats): Promise<void> {
    const legacy = createDatabaseConnection({ filename: this.readPath, readonly: true, fileMustExist: true });
    try {
      const hasTasks = legacy.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'tasks'").get();
      if (!hasTasks) {
        this.quarantine(stats, "database", this.source.sha256, "unsupported_kanban_schema", "tasks table not found");
        return;
      }
      const tasks = legacy.prepare("SELECT * FROM tasks ORDER BY created_at, id").all() as RecordValue[];
      for (const task of tasks) {
        const legacyId = asText(task.id);
        if (!legacyId) {
          this.quarantine(stats, "task:unknown", jsonHash(task), "invalid_kanban_task", "task id is missing", task);
          continue;
        }
        this.processItem(stats, `kanban-task:${legacyId}`, task, () => {
          const missionId = this.createLegacyMission({
            key: `kanban:${legacyId}`,
            title: asText(task.title, `Legacy task ${legacyId}`),
            objective: asText(task.body, asText(task.title, "Legacy board task")),
            status: task.status,
            engagement: asText(task.engagement) || undefined,
            createdAt: task.created_at,
            updatedAt: task.completed_at ?? task.started_at ?? task.created_at,
            provenance: { sourceSha256: this.source.sha256, legacyTaskId: legacyId },
          });
          const runId = this.createLegacyRun({
            key: `kanban:${legacyId}`,
            missionId,
            status: task.status,
            reason: asText(task.last_failure_error ?? task.result),
            createdAt: task.created_at,
            updatedAt: task.completed_at ?? task.started_at ?? task.created_at,
            endedAt: task.completed_at,
            provider: asText(task.agent_provider),
          });
          return { targetTable: "missions", targetId: missionId || runId };
        });
      }
    } finally { legacy.close(); }
  }

  private async importConversationState(stats: ImportStats): Promise<void> {
    const legacy = createDatabaseConnection({ filename: this.readPath, readonly: true, fileMustExist: true });
    try {
      const hasSessions = legacy.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions'").get();
      const hasMessages = legacy.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages'").get();
      if (!hasSessions || !hasMessages) {
        this.quarantine(stats, "database", this.source.sha256, "unsupported_conversation_schema", "sessions/messages tables not found");
        return;
      }
      const sessions = legacy.prepare(`
        SELECT id, source, model, started_at, ended_at, end_reason,
          input_tokens, output_tokens, estimated_cost_usd, title
        FROM sessions ORDER BY started_at, id
      `).all() as RecordValue[];
      const messageQuery = legacy.prepare(`
        SELECT id, role, content, tool_name, timestamp, token_count, finish_reason
        FROM messages WHERE session_id = ? ORDER BY timestamp, id
      `);
      for (const session of sessions) {
        const sessionKey = asText(session.id);
        if (!sessionKey) continue;
        const conversationId = stableId("conversation", this.sourceIdentity(), sessionKey);
        this.processItem(stats, `conversation-session:${sessionKey}`, session, () => {
          const startedAt = asIso(session.started_at, this.source.modifiedAt);
          const endedAt = asIso(session.ended_at, startedAt);
          this.database.prepare(`
            INSERT OR IGNORE INTO conversations (id, conversation_type, created_at, updated_at)
            VALUES (?, 'global', ?, ?)
          `).run(conversationId, startedAt, endedAt);
          this.database.prepare(`
            INSERT OR IGNORE INTO provider_turns (
              id, conversation_id, provider, model, status, input_tokens,
              output_tokens, estimated_cost, started_at, ended_at
            ) VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?)
          `).run(
            stableId("provider_turn", this.sourceIdentity(), sessionKey),
            conversationId,
            redactLegacyText(session.source ?? "legacy", 100),
            asText(session.model) ? redactLegacyText(session.model, 100) : null,
            typeof session.input_tokens === "number" && session.input_tokens >= 0 ? session.input_tokens : null,
            typeof session.output_tokens === "number" && session.output_tokens >= 0 ? session.output_tokens : null,
            typeof session.estimated_cost_usd === "number" && session.estimated_cost_usd >= 0 ? session.estimated_cost_usd : null,
            startedAt,
            endedAt,
          );
          return { targetTable: "conversations", targetId: conversationId };
        });
        const messages = messageQuery.all(sessionKey) as RecordValue[];
        messages.forEach((message, index) => this.importMessage(stats, conversationId, sessionKey, message, index));
      }
    } finally { legacy.close(); }
  }
}
