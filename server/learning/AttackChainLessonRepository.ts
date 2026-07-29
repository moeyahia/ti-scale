import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { MemoryRepository, type MemoryLifecycle, type MemoryScope } from "../memory";
import {
  buildTrainingLessonContext,
  findLessonTargetSpecificIdentifiers,
  findRejectableSecrets,
  findReusableContentIdentifiers,
  isReusableLessonSafe,
  validateAndNormalizeLesson,
  type AttackLesson,
} from "./AttackLesson";

export const ATTACK_CHAIN_ITEM_TYPES = [
  "prerequisite",
  "observed_signal",
  "ordered_step",
  "tool",
  "public_reference",
  "validation_checkpoint",
  "failure_recovery",
  "anti_reuse_warning",
] as const;

export type AttackChainItemType = (typeof ATTACK_CHAIN_ITEM_TYPES)[number];

export interface AttackChainSourceInput {
  readonly sourceType: "run_evaluation" | "legacy_training" | "operator" | "specialist_result";
  /** Opaque stable identifier only; never a path, target, URL, or source excerpt. */
  readonly sourceId: string;
  readonly sourceHash?: string;
  readonly runId?: string;
  readonly evidenceId?: string;
}

export interface AttackChainDetailInput {
  readonly title: string;
  readonly techniqueName: string;
  readonly techniqueCategory: AttackLesson["techniqueCategory"];
  readonly summary: string;
  readonly prerequisites: readonly string[];
  readonly observedSignals: readonly string[];
  readonly orderedSteps: readonly string[];
  readonly tools: readonly string[];
  readonly publicReferences: readonly string[];
  readonly validationCheckpoints: readonly string[];
  readonly failureRecovery: readonly string[];
  readonly antiReuseWarnings?: readonly string[];
  readonly expectedOutcome?: string;
  readonly reuseGuidance?: string;
  readonly confidence: number;
  readonly scope?: AttackLesson["scope"];
  readonly agentId?: string;
  readonly sources: readonly AttackChainSourceInput[];
}

export interface AttackChainItem {
  readonly id: string;
  readonly type: AttackChainItemType;
  readonly ordinal: number;
  readonly content: string;
}

export interface AttackChainSource {
  readonly id: string;
  readonly sourceType: string;
  readonly sourceId: string;
  readonly sourceHash: string | null;
  readonly runId: string | null;
  readonly evidenceId: string | null;
  readonly createdAt: string;
}

export interface AttackChainDetails {
  readonly id: string;
  readonly lessonId: string;
  readonly version: number;
  readonly techniqueName: string;
  readonly techniqueCategory: string;
  readonly summary: string;
  readonly expectedOutcome: string;
  readonly reuseGuidance: string;
  readonly contentHash: string;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly items: readonly AttackChainItem[];
  readonly sources: readonly AttackChainSource[];
}

interface DetailRow {
  readonly id: string;
  readonly lesson_id: string;
  readonly version: number;
  readonly technique_name: string;
  readonly technique_category: string;
  readonly summary: string;
  readonly expected_outcome: string;
  readonly reuse_guidance: string;
  readonly content_hash: string;
  readonly created_by: string;
  readonly created_at: string;
}

interface ItemRow {
  readonly id: string;
  readonly item_type: AttackChainItemType;
  readonly ordinal: number;
  readonly content: string;
}

interface SourceRow {
  readonly id: string;
  readonly source_type: string;
  readonly source_id: string;
  readonly source_hash: string | null;
  readonly run_id: string | null;
  readonly evidence_id: string | null;
  readonly created_at: string;
}

interface LessonRow {
  readonly id: string;
  readonly statement: string;
  readonly lesson_type: string;
  readonly applicability_scope: string;
  readonly status: AttackLesson["status"] | "under_review" | "superseded";
  readonly confidence: number;
  readonly authoring_agent_id: string | null;
}

interface RepositoryOptions {
  readonly clock?: () => Date;
}

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const SHA256 = /^[a-f0-9]{64}$/iu;
const PLACEHOLDER = /<([A-Z][A-Z0-9_]{1,63})>/gu;
const ALLOWED_PLACEHOLDERS = new Set([
  "TARGET", "TARGET_HOST", "TARGET_IP", "TARGET_URL", "TARGET_DOMAIN", "DOMAIN",
  "PORT", "PORTS", "USER_REF", "USERNAME_REF", "PASSWORD", "CREDENTIAL_REF",
  "HASH_REF", "HASH_FILE", "WORDLIST", "WORDLIST_PATH", "INPUT_PATH", "OUTPUT_PATH",
  "EVIDENCE_PATH", "LHOST", "LPORT", "RHOST", "RPORT", "INTERFACE", "PROTOCOL",
  "SERVICE", "TOOL_REF", "REFERENCE_URL",
]);
const WALKTHROUGH_REFERENCE = /(?:walk[ -]?through|write[ -]?up|solution|hack\s*the\s*box|hackthebox|tryhackme|vulnhub|\bhtb\b|\bctf\b)/iu;
const COMMAND_SIGNAL = /(?:^|\s)(?:\$|sudo\s+|[a-z0-9_.+-]+\s+--?[a-z0-9-]+\b|`[^`]+`)/iu;
const LITERAL_PATH = /(?:^|\s)(?:\.{0,2}\/|~\/|\/[A-Za-z0-9_.-])[^\s]*/u;
const CREDENTIAL_ARGUMENT = /(?:^|\s)(?:-u|--user(?:name)?|-p|--pass(?:word)?|--token|--key)\s+(?!<(?:USER_REF|USERNAME_REF|PASSWORD|CREDENTIAL_REF|HASH_REF)>)[^\s]+/iu;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function stableId(prefix: string, value: string): string {
  return `${prefix}_${sha256(value).slice(0, 32)}`;
}

export function canonicalLessonMemoryNodeId(lessonId: string): string {
  return stableId("mem_lesson", lessonId);
}

function validationErrors(validation: ReturnType<typeof validateAndNormalizeLesson>): readonly string[] {
  return "errors" in validation && Array.isArray(validation.errors)
    ? validation.errors
    : ["attack-chain validation failed"];
}

function assertOpaque(value: string, label: string): void {
  if (!OPAQUE_ID.test(value)) throw new Error(`${label} must be an opaque stable identifier`);
}

function validateReference(reference: string): void {
  if (WALKTHROUGH_REFERENCE.test(reference)) {
    throw new Error("walkthrough, box, CTF, and solution references are not reusable attack knowledge");
  }
  if (findRejectableSecrets(reference).length || findReusableContentIdentifiers(reference).some((kind) => kind !== "literal_url_outside_references" && kind !== "literal_domain_outside_references")) {
    throw new Error("public reference contains target-specific or secret material");
  }
  if (!/^https?:\/\//iu.test(reference)) {
    if (!/^(?:CVE-\d{4}-\d{4,}|CWE-\d+|MITRE ATT&CK T\d{4}(?:\.\d{3})?|[A-Za-z][A-Za-z0-9 .:+_-]{2,120})$/u.test(reference)) {
      throw new Error("reference must be a public technical URL or recognized technique/advisory identifier");
    }
    return;
  }
  let parsed: URL;
  try { parsed = new URL(reference); }
  catch { throw new Error("public reference URL is invalid"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
    throw new Error("public references must use credential-free HTTPS URLs without fragments");
  }
  const host = parsed.hostname.toLocaleLowerCase("en-US");
  if (
    host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") ||
    host.endsWith(".lan") || host.endsWith(".test") || host.endsWith(".htb") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(host) || host.includes(":")
  ) {
    throw new Error("public reference points to a target/private host");
  }
}

function validateStep(step: string, tools: readonly string[]): void {
  const identifiers = findReusableContentIdentifiers(step);
  if (identifiers.length || findRejectableSecrets(step).length) {
    throw new Error(`ordered step contains target-specific material: ${identifiers.join(", ") || "secret"}`);
  }
  const placeholders = [...step.matchAll(PLACEHOLDER)].map((match) => match[1]);
  for (const placeholder of placeholders) {
    if (!ALLOWED_PLACEHOLDERS.has(placeholder)) throw new Error(`unsupported command placeholder <${placeholder}>`);
  }
  const toolSignal = tools.some((tool) => {
    const executable = tool.split(/\s+/u)[0]?.toLocaleLowerCase("en-US");
    return Boolean(executable) && new RegExp(`(?:^|\\s)${executable!.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}(?:\\s|$)`, "iu").test(step);
  });
  const commandLike = COMMAND_SIGNAL.test(step) || toolSignal;
  if (!commandLike) return;
  if (placeholders.length === 0) {
    throw new Error("raw command-like steps must parameterize targets and inputs with approved placeholders");
  }
  if (LITERAL_PATH.test(step.replace(/<[^>]+>/gu, ""))) {
    throw new Error("raw command-like steps must use path placeholders instead of literal paths");
  }
  if (CREDENTIAL_ARGUMENT.test(step)) {
    throw new Error("raw command-like steps must use credential placeholders");
  }
}

function validatedAttackChain(input: AttackChainDetailInput): AttackLesson {
  if (input.validationCheckpoints.length === 0) throw new Error("attack chain requires a validation checkpoint");
  if (input.failureRecovery.length === 0) throw new Error("attack chain requires bounded failure recovery guidance");
  if (input.publicReferences.length === 0) throw new Error("attack chain requires a public technique/tool/advisory reference");
  const raw = {
    kind: "attack_chain",
    title: input.title,
    techniqueName: input.techniqueName,
    techniqueCategory: input.techniqueCategory,
    summary: input.summary,
    prerequisites: [...input.prerequisites],
    observedSignals: [...input.observedSignals],
    stepsThatWorked: [...input.orderedSteps],
    toolsUsed: [...input.tools],
    references: [...input.publicReferences],
    verificationMethod: input.validationCheckpoints.join("; "),
    outcome: input.expectedOutcome ?? "",
    reuseGuidance: input.reuseGuidance ?? "",
    antiReuseWarnings: [...(input.antiReuseWarnings ?? [])],
    failedAttempts: [...input.failureRecovery],
    evidenceIds: input.sources.flatMap((source) => source.evidenceId ? [source.evidenceId] : []),
    sourceRunId: input.sources.find((source) => source.runId)?.runId,
    sourceStepIds: [],
    confidence: input.confidence,
    scope: input.scope ?? "mission",
    agentId: input.agentId,
  };
  const validation = validateAndNormalizeLesson(raw);
  if (!validation.ok || !validation.lesson) throw new Error(validationErrors(validation).join("; "));
  const lesson = validation.lesson as AttackLesson;
  if (lesson.kind !== "attack_chain" || !isReusableLessonSafe(lesson)) {
    throw new Error("attack-chain content failed reusable-memory safety validation");
  }
  const identifiers = findLessonTargetSpecificIdentifiers(lesson);
  if (identifiers.length) throw new Error(`attack chain contains target-specific identifiers: ${identifiers.join(", ")}`);
  if (!(lesson.prerequisites.length || lesson.observedSignals.length)) {
    throw new Error("attack chain requires at least one prerequisite or observed signal");
  }
  if (!lesson.stepsThatWorked.length || !lesson.toolsUsed.length) {
    throw new Error("attack chain requires ordered steps and tools");
  }
  for (const tool of lesson.toolsUsed) {
    if (!/^[A-Za-z][A-Za-z0-9+_.:-]{0,80}(?: [A-Za-z][A-Za-z0-9+_.:-]{0,80})?$/u.test(tool)) {
      throw new Error("tools must be names, not command lines or target-specific invocations");
    }
  }
  for (const reference of lesson.references) validateReference(reference);
  for (const step of lesson.stepsThatWorked) validateStep(step, lesson.toolsUsed);
  return lesson;
}

function detailsFromRows(row: DetailRow, items: readonly ItemRow[], sources: readonly SourceRow[]): AttackChainDetails {
  return {
    id: row.id,
    lessonId: row.lesson_id,
    version: row.version,
    techniqueName: row.technique_name,
    techniqueCategory: row.technique_category,
    summary: row.summary,
    expectedOutcome: row.expected_outcome,
    reuseGuidance: row.reuse_guidance,
    contentHash: row.content_hash,
    createdBy: row.created_by,
    createdAt: row.created_at,
    items: items.map((item) => ({ id: item.id, type: item.item_type, ordinal: item.ordinal, content: item.content })),
    sources: sources.map((source) => ({
      id: source.id,
      sourceType: source.source_type,
      sourceId: source.source_id,
      sourceHash: source.source_hash,
      runId: source.run_id,
      evidenceId: source.evidence_id,
      createdAt: source.created_at,
    })),
  };
}

/** Canonical append-only repository for safe, executable attack-chain candidates. */
export class AttackChainLessonRepository {
  readonly #clock: () => Date;

  constructor(readonly database: SqliteDatabase, options: RepositoryOptions = {}) {
    this.#clock = options.clock ?? (() => new Date());
  }

  saveDetails(lessonId: string, input: AttackChainDetailInput, createdBy: string): AttackChainDetails {
    assertOpaque(lessonId, "lesson ID");
    assertOpaque(createdBy, "attack-chain author");
    const normalized = validatedAttackChain(input);
    return inImmediateTransaction(this.database, () => {
      const lesson = this.database.prepare("SELECT * FROM lessons WHERE id = ?").get(lessonId) as LessonRow | undefined;
      if (!lesson) throw new Error(`Lesson not found: ${lessonId}`);
      if (lesson.lesson_type !== "attack_chain") throw new Error("structured attack-chain details require lesson_type=attack_chain");
      if (lesson.status === "verified") throw new Error("verified attack-chain details are immutable; create a reviewed successor lesson");

      const itemGroups: Readonly<Record<AttackChainItemType, readonly string[]>> = {
        prerequisite: normalized.prerequisites,
        observed_signal: normalized.observedSignals,
        ordered_step: normalized.stepsThatWorked,
        tool: normalized.toolsUsed,
        public_reference: normalized.references,
        validation_checkpoint: input.validationCheckpoints,
        failure_recovery: normalized.failedAttempts,
        anti_reuse_warning: normalized.antiReuseWarnings,
      };
      const content = {
        techniqueName: normalized.techniqueName,
        techniqueCategory: normalized.techniqueCategory,
        summary: normalized.summary,
        expectedOutcome: normalized.outcome,
        reuseGuidance: normalized.reuseGuidance,
        items: itemGroups,
      };
      const contentHash = sha256(stableJson(content));
      const existing = this.database.prepare(`
        SELECT * FROM lesson_attack_chain_details WHERE lesson_id = ? AND content_hash = ?
      `).get(lessonId, contentHash) as DetailRow | undefined;
      const now = this.#clock().toISOString();
      let detail = existing;
      if (!detail) {
        const version = Number((this.database.prepare(`
          SELECT COALESCE(MAX(version), 0) + 1 AS version
          FROM lesson_attack_chain_details WHERE lesson_id = ?
        `).get(lessonId) as { version: number }).version);
        const detailId = stableId("chain", `${lessonId}\n${contentHash}`);
        this.database.prepare(`
          INSERT INTO lesson_attack_chain_details (
            id, lesson_id, schema_version, version, technique_name,
            technique_category, summary, expected_outcome, reuse_guidance,
            content_hash, created_by, created_at
          ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          detailId, lessonId, version, normalized.techniqueName,
          normalized.techniqueCategory, normalized.summary, normalized.outcome,
          normalized.reuseGuidance, contentHash, createdBy, now,
        );
        for (const type of ATTACK_CHAIN_ITEM_TYPES) {
          itemGroups[type].forEach((item, ordinal) => {
            this.database.prepare(`
              INSERT INTO lesson_attack_chain_items (
                id, detail_id, item_type, ordinal, content, content_hash,
                metadata_json, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)
            `).run(
              stableId("chainitem", `${detailId}\n${type}\n${ordinal}\n${item}`),
              detailId, type, ordinal, item, sha256(item), now,
            );
          });
        }
        detail = this.database.prepare("SELECT * FROM lesson_attack_chain_details WHERE id = ?")
          .get(detailId) as DetailRow;
      }
      for (const source of input.sources) this.#saveSource(lessonId, detail.id, source, now);
      return this.#hydrate(detail);
    });
  }

  getLatest(lessonId: string, options: { readonly verifiedOnly?: boolean } = {}): AttackChainDetails | null {
    assertOpaque(lessonId, "lesson ID");
    const row = this.database.prepare(`
      SELECT d.* FROM lesson_attack_chain_details d
      JOIN lessons l ON l.id = d.lesson_id
      WHERE d.lesson_id = ? ${options.verifiedOnly ? "AND l.status = 'verified'" : ""}
      ORDER BY d.version DESC LIMIT 1
    `).get(lessonId) as DetailRow | undefined;
    return row ? this.#hydrate(row) : null;
  }

  listVerified(options: { readonly engagementId?: string; readonly missionId?: string; readonly limit?: number } = {}): AttackChainDetails[] {
    const clauses = ["l.status = 'verified'", "l.lesson_type = 'attack_chain'"];
    const params: unknown[] = [];
    if (options.engagementId) {
      clauses.push("(l.engagement_id = ? OR l.applicability_scope = 'global')");
      params.push(options.engagementId);
    }
    if (options.missionId) {
      clauses.push("(l.mission_id = ? OR l.mission_id IS NULL)");
      params.push(options.missionId);
    }
    const limit = Math.max(1, Math.min(100, options.limit ?? 20));
    params.push(limit);
    const rows = this.database.prepare(`
      SELECT d.* FROM lesson_attack_chain_details d
      JOIN lessons l ON l.id = d.lesson_id
      WHERE ${clauses.join(" AND ")}
        AND d.version = (
          SELECT MAX(latest.version) FROM lesson_attack_chain_details latest
          WHERE latest.lesson_id = d.lesson_id
        )
      ORDER BY l.updated_at DESC, d.lesson_id LIMIT ?
    `).all(...params) as DetailRow[];
    return rows.map((row) => this.#hydrate(row));
  }

  buildVerifiedContext(options: {
    readonly engagementId?: string;
    readonly missionId?: string;
    readonly limit?: number;
  } = {}): string {
    const attackLessons = this.listVerified(options).map((detail): AttackLesson | null => {
      const lesson = this.database.prepare("SELECT * FROM lessons WHERE id = ?")
        .get(detail.lessonId) as LessonRow | undefined;
      if (!lesson || lesson.status !== "verified") return null;
      const byType = (type: AttackChainItemType) => detail.items
        .filter((item) => item.type === type)
        .sort((a, b) => a.ordinal - b.ordinal)
        .map((item) => item.content);
      const evidenceIds = (this.database.prepare(`
        SELECT DISTINCT evidence_id FROM lesson_evidence
        WHERE lesson_id = ? AND relationship = 'supports' AND evidence_id IS NOT NULL
        ORDER BY evidence_id
      `).all(detail.lessonId) as Array<{ evidence_id: string }>).map((row) => row.evidence_id);
      const run = this.database.prepare(`
        SELECT run_id FROM lesson_evidence
        WHERE lesson_id = ? AND relationship = 'supports' AND run_id IS NOT NULL
        ORDER BY created_at LIMIT 1
      `).get(detail.lessonId) as { run_id: string } | undefined;
      const scope: AttackLesson["scope"] = ["global", "project", "lab", "mission", "agent"].includes(lesson.applicability_scope)
        ? lesson.applicability_scope as AttackLesson["scope"]
        : lesson.applicability_scope === "engagement" ? "project" : "mission";
      return {
        id: detail.lessonId,
        category: "verified_attack_lesson",
        kind: "attack_chain",
        title: lesson.statement,
        techniqueName: detail.techniqueName,
        techniqueCategory: detail.techniqueCategory as AttackLesson["techniqueCategory"],
        summary: detail.summary,
        prerequisites: byType("prerequisite"),
        observedSignals: byType("observed_signal"),
        stepsThatWorked: byType("ordered_step"),
        toolsUsed: byType("tool"),
        references: byType("public_reference"),
        evidenceIds,
        sourceRunId: run?.run_id,
        sourceStepIds: [],
        verificationMethod: byType("validation_checkpoint").join("; "),
        outcome: detail.expectedOutcome,
        confidence: lesson.confidence,
        reuseGuidance: detail.reuseGuidance,
        antiReuseWarnings: byType("anti_reuse_warning"),
        failedAttempts: byType("failure_recovery"),
        scope,
        status: "verified",
        createdAt: detail.createdAt,
        agentId: lesson.authoring_agent_id ?? undefined,
      };
    }).filter((lesson): lesson is AttackLesson => Boolean(lesson));
    return buildTrainingLessonContext(attackLessons, {
      max: options.limit,
      header: "=== VERIFIED EXECUTABLE ATTACK CHAINS (independently approved) ===",
    });
  }

  synchronizeMemoryLifecycle(
    lessonId: string,
    status: "proposed" | "under_review" | "verified" | "rejected" | "stale" | "superseded",
    actorId: string,
  ): string | null {
    const lesson = this.database.prepare(`
      SELECT id, statement, lesson_type, applicability_scope, engagement_id,
        mission_id, status, confidence, authoring_agent_id
      FROM lessons WHERE id = ?
    `).get(lessonId) as (LessonRow & { engagement_id: string | null; mission_id: string | null }) | undefined;
    if (!lesson || lesson.lesson_type !== "attack_chain") return null;
    const details = this.getLatest(lessonId, { verifiedOnly: status === "verified" });
    if (status === "verified" && !details) throw new Error("verified attack chain has no executable details");
    const memory = new MemoryRepository(this.database, { clock: this.#clock });
    const nodeId = canonicalLessonMemoryNodeId(lessonId);
    const existing = memory.getNode(nodeId, true);
    const lifecycle: Exclude<MemoryLifecycle, "forgotten" | "confirmed"> = status === "verified"
      ? "verified"
      : status === "stale" ? "stale"
      : status === "superseded" ? "superseded"
      : status === "rejected" ? "disputed"
      : "candidate";
    const scope: MemoryScope = lesson.engagement_id
      ? { kind: "engagement", engagementId: lesson.engagement_id }
      : lesson.mission_id
        ? { kind: "mission", missionId: lesson.mission_id }
        : { kind: "global" };
    const body = details ? this.#contextBody(details) : "Pending independent review; executable details are not trusted planning context.";
    if (!existing) {
      memory.createNode({
        id: nodeId,
        nodeType: "lesson",
        title: lesson.statement,
        summary: details?.summary ?? lesson.statement,
        body,
        scope,
        sensitivity: "private",
        confidence: lesson.confidence,
        lifecycleStatus: lifecycle,
        confirmationState: lifecycle === "verified" ? "not_required" : "pending",
        provenance: {
          method: "derived",
          explanation: "Projected from the independently reviewed canonical lesson and append-only attack-chain details.",
          sources: [{
            sourceType: "lesson",
            sourceId: lessonId,
            acquiredAt: details?.createdAt ?? this.#clock().toISOString(),
            sourceHash: details?.contentHash,
          }],
        },
        authorType: "operator",
        authorId: actorId,
        retentionPolicy: {
          allowAutonomous: lifecycle === "verified",
          allowGuided: lifecycle === "verified",
        },
      });
      return nodeId;
    }
    memory.correctNode(nodeId, {
      title: lesson.statement,
      summary: details?.summary ?? lesson.statement,
      body,
      scope,
      confidence: lesson.confidence,
      lifecycleStatus: lifecycle,
      confirmationState: lifecycle === "verified" ? "not_required" : "pending",
      retentionPolicy: {
        ...existing.retentionPolicy,
        allowAutonomous: lifecycle === "verified",
        allowGuided: lifecycle === "verified",
      },
      authorType: "operator",
      authorId: actorId,
      changeReason: `Canonical lesson review transitioned to ${status}`,
    });
    return nodeId;
  }

  #saveSource(lessonId: string, detailId: string, source: AttackChainSourceInput, now: string): void {
    assertOpaque(source.sourceId, "attack-chain source ID");
    if (source.sourceHash && !SHA256.test(source.sourceHash)) throw new Error("attack-chain source hash must be SHA-256");
    if (source.runId) {
      assertOpaque(source.runId, "source run ID");
      if (!this.database.prepare("SELECT 1 FROM runs WHERE id = ?").get(source.runId)) {
        throw new Error(`attack-chain source run does not exist: ${source.runId}`);
      }
    }
    if (source.evidenceId) {
      assertOpaque(source.evidenceId, "source evidence ID");
      if (!this.database.prepare(`SELECT 1 FROM evidence WHERE id = ? AND ${verifiedEvidenceSql("evidence")}`).get(source.evidenceId)) {
        throw new Error(`attack-chain source evidence is missing or unverified: ${source.evidenceId}`);
      }
    }
    const sourceKey = `${lessonId}\n${source.sourceType}\n${source.sourceId}\n${source.runId ?? ""}\n${source.evidenceId ?? ""}`;
    this.database.prepare(`
      INSERT OR IGNORE INTO lesson_attack_chain_sources (
        id, lesson_id, detail_id, source_type, source_id, source_hash,
        run_id, evidence_id, provenance_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      stableId("chainsrc", sourceKey), lessonId, detailId, source.sourceType,
      source.sourceId, source.sourceHash ?? null, source.runId ?? null,
      source.evidenceId ?? null,
      stableJson({ method: source.sourceType, identifiersOnly: true, contentRetained: false }),
      now,
    );
  }

  #hydrate(row: DetailRow): AttackChainDetails {
    const items = this.database.prepare(`
      SELECT id, item_type, ordinal, content FROM lesson_attack_chain_items
      WHERE detail_id = ? ORDER BY item_type, ordinal
    `).all(row.id) as ItemRow[];
    const sources = this.database.prepare(`
      SELECT id, source_type, source_id, source_hash, run_id, evidence_id, created_at
      FROM lesson_attack_chain_sources WHERE detail_id = ? ORDER BY created_at, id
    `).all(row.id) as SourceRow[];
    return detailsFromRows(row, items, sources);
  }

  #contextBody(details: AttackChainDetails): string {
    const items = (type: AttackChainItemType) => details.items
      .filter((item) => item.type === type)
      .sort((a, b) => a.ordinal - b.ordinal)
      .map((item) => item.content);
    return [
      `Technique: ${details.techniqueName}`,
      `Category: ${details.techniqueCategory}`,
      `Summary: ${details.summary}`,
      `Prerequisites: ${items("prerequisite").join("; ")}`,
      `Observed signals: ${items("observed_signal").join("; ")}`,
      `Ordered steps: ${items("ordered_step").map((step, index) => `${index + 1}) ${step}`).join(" -> ")}`,
      `Tools: ${items("tool").join(", ")}`,
      `Validation checkpoints: ${items("validation_checkpoint").join("; ")}`,
      `Failure recovery: ${items("failure_recovery").join("; ")}`,
      `Expected outcome: ${details.expectedOutcome}`,
      `Reuse guidance: ${details.reuseGuidance}`,
      `Anti-reuse warnings: ${items("anti_reuse_warning").join("; ")}`,
      `Public references: ${items("public_reference").join("; ")}`,
    ].join("\n");
  }
}

/** Service boundary used by runtime, migration, review, and planning adapters. */
export class AttackChainLearningService {
  readonly repository: AttackChainLessonRepository;

  constructor(database: SqliteDatabase, options: RepositoryOptions = {}) {
    this.repository = new AttackChainLessonRepository(database, options);
  }

  retainCandidateDetails(lessonId: string, input: AttackChainDetailInput, createdBy: string): AttackChainDetails {
    return this.repository.saveDetails(lessonId, input, createdBy);
  }

  detailsForReview(lessonId: string): AttackChainDetails | null {
    return this.repository.getLatest(lessonId);
  }

  verifiedPlanningContext(options: Parameters<AttackChainLessonRepository["buildVerifiedContext"]>[0] = {}): string {
    return this.repository.buildVerifiedContext(options);
  }

  synchronizeMemoryLifecycle(
    lessonId: string,
    status: Parameters<AttackChainLessonRepository["synchronizeMemoryLifecycle"]>[1],
    actorId: string,
  ): string | null {
    return this.repository.synchronizeMemoryLifecycle(lessonId, status, actorId);
  }
}
