import { createHash } from "node:crypto";
import type { BrainContextResult } from "../brain-runtime";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { digestCanonicalJson } from "../mcp";
import { MemoryRepository, type MemoryNode, type MemoryNodeType } from "../memory";
import { memoryNodeMatchesPolicy } from "../memory/MemoryScopePolicy";
import { canonicalJson, hashCanonical } from "../missions/canonical";
import type { DurableAction } from "../orchestration";
import {
  AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION,
} from "./AutonomousWebSurfaceBaseline";
import type { AutonomousWebSurfacePhase } from "./AutonomousWebSurfaceExecution";

export const AUTONOMOUS_WEB_PHASE_MEMORY_GUARD_SCHEMA_VERSION =
  "ti-scale.autonomous-web-phase-memory-guard.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const VERIFIED_BLOCK_CONFIDENCE = 0.85;
const MINIMUM_REPRODUCIBILITY_COUNT = 2;
const HANG_OR_CRASH = /\b(?:hang(?:s|ing)?|hung|wedg(?:e|ed|ing)|stuck|unresponsive|stopped\s+responding|crash(?:ed|es|ing)?|segfault|segmentation\s+fault)\b/iu;
const PRODUCT_STOP_WORDS = new Set([
  "application", "http", "https", "product", "server", "service", "services",
  "software", "technology", "web",
]);
const TECHNOLOGY_TYPES = new Set<MemoryNodeType>([
  "technology_product", "operating_system", "kernel", "framework", "runtime",
  "database", "firewall", "waf", "proxy", "security_control",
]);
const VERSION_TYPES = new Set<MemoryNodeType>([
  "exact_version_fingerprint",
]);
const RECOVERY_TYPES = new Set<MemoryNodeType>([
  "recovery_pattern", "health_check", "target_state_transition",
]);

interface WhatWebEvidenceRow {
  readonly id: string;
  readonly extracted_text: string | null;
  readonly content_hash: string;
  readonly provenance_json: string;
  readonly target: string | null;
  readonly source_ordinal: number | null;
  readonly current_ordinal: number;
  readonly source_plan_id: string | null;
  readonly current_plan_id: string;
}

interface HazardProfileRow {
  readonly node_id: string;
  readonly product_node_ids_json: string;
  readonly version_node_ids_json: string;
  readonly stack_node_ids_json: string;
  readonly observed_symptom: string;
  readonly reproducibility_count: number;
  readonly receipt_backed_occurrence_count: number;
  readonly recovery_pattern_node_id: string | null;
  readonly confidence: number;
  readonly fresh_until: string | null;
}

export interface AutonomousWebPhaseMemoryEvidence {
  readonly sourceEvidenceIds: readonly string[];
  /** Local retrieval/matching input. It is never persisted in the guard receipt. */
  readonly technologySignals: readonly string[];
  readonly signalEvidenceSha256: string;
}

export type AutonomousWebPhaseMemoryGuardDecision =
  | "allow"
  | "block_endpoint_discovery";

export interface WebPhaseMemoryGuardReceipt {
  readonly schemaVersion: typeof AUTONOMOUS_WEB_PHASE_MEMORY_GUARD_SCHEMA_VERSION;
  readonly receiptId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly phase: AutonomousWebSurfacePhase;
  readonly contextPackId: string;
  readonly contextRetrievalAuditRecordId: string;
  readonly influenceAuditRecordId: string;
  readonly sourceEvidenceIds: readonly string[];
  readonly signalEvidenceSha256: string;
  readonly matchedTechnologyNodeIds: readonly string[];
  readonly matchedVersionNodeIds: readonly string[];
  readonly matchedHazardNodeIds: readonly string[];
  readonly matchedRecoveryNodeIds: readonly string[];
  readonly usedNodeIds: readonly string[];
  readonly ignoredNodeIds: readonly string[];
  readonly decision: AutonomousWebPhaseMemoryGuardDecision;
  readonly reasonCode:
    | "no_relevant_memory"
    | "no_verified_technology_hazard_match"
    | "verified_hang_or_crash_hazard_match";
  readonly createdAt: string;
  readonly receiptSha256: string;
}

export class AutonomousWebPhaseMemoryGuardError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "AutonomousWebPhaseMemoryGuardError";
  }
}

function plain(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function object(value: string | null, label: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value ?? "null") as unknown;
    if (!plain(parsed)) throw new Error("not an object");
    return parsed;
  } catch {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_source_malformed",
      `The verified ${label} used by the memory guard is malformed.`,
    );
  }
}

function strings(value: unknown, maximum = 128): readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) return [];
  return Object.freeze([...new Set(value.flatMap((item) => {
    if (typeof item !== "string") return [];
    const normalized = item.normalize("NFKC").replace(/[\u0000-\u001F\u007F]/gu, " ")
      .trim().replace(/\s+/gu, " ").slice(0, 300);
    return normalized ? [normalized] : [];
  }))].sort());
}

function ids(value: string, label: string): readonly string[] {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_profile_malformed",
      `${label} is malformed.`,
    );
  }
  if (!Array.isArray(parsed) || parsed.length > 128
    || parsed.some((item) => typeof item !== "string" || !item.trim())) {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_profile_malformed",
      `${label} must be a bounded array of memory-node IDs.`,
    );
  }
  return Object.freeze([...new Set(parsed as string[])].sort());
}

function normalized(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US")
    .replace(/[^\p{L}\p{N}]+/gu, " ").trim().replace(/\s+/gu, " ");
}

function body(node: MemoryNode): Readonly<Record<string, unknown>> {
  if (!node.body.trim()) return {};
  try {
    const parsed = JSON.parse(node.body) as unknown;
    return plain(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function productMatchesSignal(node: MemoryNode, signal: string): boolean {
  const signalWords = new Set(normalized(signal).split(" ").filter(Boolean));
  const titleWords = normalized(node.title).split(" ").filter(Boolean);
  const distinctive = titleWords.filter((word) => word.length >= 3 && !PRODUCT_STOP_WORDS.has(word));
  const directMatches = distinctive.filter((word) => signalWords.has(word)).length;
  if (directMatches >= Math.min(2, distinctive.length)) return distinctive.length > 0;
  const acronym = distinctive.map((word) => word[0]).join("");
  const vendorNeutralAcronym = distinctive.slice(1).map((word) => word[0]).join("");
  return (acronym.length >= 2 && signalWords.has(acronym))
    || (vendorNeutralAcronym.length >= 2 && signalWords.has(vendorNeutralAcronym));
}

function versionMatchesSignal(node: MemoryNode, signal: string): boolean {
  const exactVersion = body(node).exactVersion;
  if (typeof exactVersion !== "string" || !exactVersion.trim()) return false;
  const version = normalized(exactVersion);
  return version.length > 0 && (` ${normalized(signal)} `).includes(` ${version} `);
}

function activeAt(value: string | null, now: Date): boolean {
  return value === null || (Number.isFinite(Date.parse(value)) && Date.parse(value) > now.getTime());
}

function receiptKey(receiptId: string): string {
  return `runtime.autonomous-web-memory-guard.${receiptId}`;
}

/**
 * Reads the exact prior verified WhatWeb record without deriving or authorizing
 * any origin. The returned banner strings are local matching data only.
 */
export function inspectAutonomousWebPhaseMemoryEvidence(
  database: SqliteDatabase,
  action: DurableAction,
  phase: AutonomousWebSurfacePhase,
): AutonomousWebPhaseMemoryEvidence {
  if (phase !== "endpoint_discovery") {
    return Object.freeze({
      sourceEvidenceIds: Object.freeze([]),
      technologySignals: Object.freeze([]),
      signalEvidenceSha256: digestCanonicalJson([], { maxBytes: 1_024, maxDepth: 4 }).sha256,
    });
  }
  const rows = database.prepare(`
    SELECT e.id, e.extracted_text, e.content_hash, e.provenance_json,
      source.scoped_target AS target, source_step.ordinal AS source_ordinal,
      current_step.ordinal AS current_ordinal, source_step.plan_id AS source_plan_id,
      current_step.plan_id AS current_plan_id
    FROM actions current
    JOIN plan_steps current_step ON current_step.id = current.step_id
    JOIN evidence e ON e.mission_id = current.mission_id AND e.run_id = current.run_id
      AND e.verification_state = 'verified' AND e.evidence_type = ?
    JOIN actions source ON source.id = e.action_id AND source.run_id = current.run_id
      AND source.mission_id = current.mission_id AND source.action_type = ?
    JOIN plan_steps source_step ON source_step.id = source.step_id
    WHERE current.id = ? AND source.status = 'succeeded'
      AND source.scoped_target = current.scoped_target
    ORDER BY e.acquired_at DESC, e.id DESC LIMIT 2
  `).all(
    AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
    AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    action.id,
  ) as WhatWebEvidenceRow[];
  // No WhatWeb evidence is valid only for an eventually not-applicable empty
  // web surface. The ordinary authorization boundary validates that lineage.
  if (rows.length === 0) {
    return Object.freeze({
      sourceEvidenceIds: Object.freeze([]),
      technologySignals: Object.freeze([]),
      signalEvidenceSha256: digestCanonicalJson([], { maxBytes: 1_024, maxDepth: 4 }).sha256,
    });
  }
  if (rows.length !== 1) {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_source_ambiguous",
      "The endpoint memory guard found more than one current verified technology fingerprint.",
    );
  }
  const row = rows[0]!;
  if (row.target !== action.target || row.source_plan_id !== row.current_plan_id
    || row.source_ordinal === null || row.source_ordinal >= row.current_ordinal
    || !SHA256.test(row.content_hash)) {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_source_binding_invalid",
      "The technology fingerprint does not precede this endpoint action in the same immutable plan.",
    );
  }
  const content = object(row.extracted_text, "technology-fingerprint content");
  const provenance = object(row.provenance_json, "technology-fingerprint provenance");
  if (digestCanonicalJson(content, { maxBytes: 4 * 1024 * 1024, maxDepth: 32 }).sha256
      !== row.content_hash
    || content.parentTarget !== action.target
    || content.phase !== "whatweb_fingerprint"
    || !Array.isArray(content.responses)
    || provenance.schemaVersion !== AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION
    || provenance.method !== "deterministic_derived_origin_local_process_validation"
    || provenance.virtualToolId !== AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
    || provenance.rawProcessOutputPromoted !== false) {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_source_integrity_invalid",
      "The verified technology fingerprint failed its immutable local provenance check.",
    );
  }
  const signals = Object.freeze([...new Set((content.responses as unknown[]).flatMap((response) => {
    if (!plain(response) || !plain(response.fingerprint)
      || !Array.isArray(response.fingerprint.httpServerSignals)
      || !Array.isArray(response.fingerprint.poweredBySignals)
      || response.fingerprint.httpServerSignals.some((item) => typeof item !== "string")
      || response.fingerprint.poweredBySignals.some((item) => typeof item !== "string")) {
      throw new AutonomousWebPhaseMemoryGuardError(
        "autonomous_web_memory_guard_signal_shape_invalid",
        "The verified technology fingerprint does not contain the expected bounded signal arrays.",
      );
    }
    return [
      ...strings(response.fingerprint.httpServerSignals),
      ...strings(response.fingerprint.poweredBySignals),
    ];
  }))].sort());
  const sourceEvidenceIds = Object.freeze([row.id]);
  return Object.freeze({
    sourceEvidenceIds,
    technologySignals: signals,
    signalEvidenceSha256: digestCanonicalJson({
      evidenceId: row.id,
      contentHash: row.content_hash,
      signals,
    }, { maxBytes: 128 * 1_024, maxDepth: 8 }).sha256,
  });
}

function canonicalEligibleNodes(
  database: SqliteDatabase,
  action: DurableAction,
  context: BrainContextResult,
  now: Date,
): ReadonlyMap<string, MemoryNode> {
  if (context.hook !== "phase_transition" || context.contextPack.releaseDataClass !== "canonical"
    || context.contextPack.journey !== "autonomous"
    || context.contextPack.missionId !== action.missionId
    || context.contextPack.runId !== action.runId
    || context.contextPack.actionId !== action.id
    || (action.stepId && context.contextPack.stepId !== action.stepId)) {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_context_binding_invalid",
      "The phase Context Pack is not bound to this exact Autonomous web action.",
    );
  }
  const packIds = [...context.contextPack.items.map(({ nodeId }) => nodeId)].sort();
  const itemIds = [...context.items.map(({ node }) => node.id)].sort();
  if (packIds.join("\u0000") !== itemIds.join("\u0000") || new Set(itemIds).size !== itemIds.length) {
    throw new AutonomousWebPhaseMemoryGuardError(
      "autonomous_web_memory_guard_context_items_invalid",
      "The phase Context Pack items do not match the retrieved canonical memory nodes.",
    );
  }
  const repository = new MemoryRepository(database, { clock: () => now });
  const eligible = new Map<string, MemoryNode>();
  for (const item of context.items) {
    const canonical = repository.getNode(item.node.id);
    if (!canonical || canonical.version !== item.node.version
      || canonical.nodeType !== item.node.nodeType
      || canonical.lifecycleStatus !== item.node.lifecycleStatus
      || canonical.confirmationState !== item.node.confirmationState
      || digestCanonicalJson(canonical, { maxBytes: 1_048_576, maxDepth: 32 }).sha256
        !== digestCanonicalJson(item.node, { maxBytes: 1_048_576, maxDepth: 32 }).sha256) {
      continue;
    }
    if (!memoryNodeMatchesPolicy(
      database,
      canonical,
      context.contextPack.scopePolicy,
      now.toISOString(),
    ) || canonical.confirmationState !== "confirmed"
      || !["confirmed", "verified"].includes(canonical.lifecycleStatus)) continue;
    eligible.set(canonical.id, canonical);
  }
  return eligible;
}

function persistReceipt(
  database: SqliteDatabase,
  bodyValue: Omit<WebPhaseMemoryGuardReceipt, "receiptSha256">,
): WebPhaseMemoryGuardReceipt {
  const receipt = Object.freeze({
    ...bodyValue,
    receiptSha256: digestCanonicalJson(bodyValue, {
      maxBytes: 512 * 1_024,
      maxDepth: 20,
    }).sha256,
  });
  return inImmediateTransaction(database, () => {
    const key = receiptKey(receipt.receiptId);
    const existing = database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(key) as { readonly value_json: string } | undefined;
    if (existing) {
      let parsed: WebPhaseMemoryGuardReceipt;
      try { parsed = JSON.parse(existing.value_json) as WebPhaseMemoryGuardReceipt; } catch {
        throw new AutonomousWebPhaseMemoryGuardError(
          "autonomous_web_memory_guard_receipt_malformed",
          "The durable web-phase memory guard receipt is malformed.",
        );
      }
      if (digestCanonicalJson(parsed, { maxBytes: 512 * 1_024, maxDepth: 20 }).sha256
        !== digestCanonicalJson(receipt, { maxBytes: 512 * 1_024, maxDepth: 20 }).sha256) {
        throw new AutonomousWebPhaseMemoryGuardError(
          "autonomous_web_memory_guard_receipt_conflict",
          "A different memory influence receipt already exists for this exact action and Context Pack.",
        );
      }
      return Object.freeze(parsed);
    }
    const previous = database.prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1")
      .get() as { readonly record_hash: string } | undefined;
    const details = Object.freeze({
      receiptId: receipt.receiptId,
      receiptSha256: receipt.receiptSha256,
      contextPackId: receipt.contextPackId,
      contextRetrievalAuditRecordId: receipt.contextRetrievalAuditRecordId,
      decision: receipt.decision,
      reasonCode: receipt.reasonCode,
      sourceEvidenceIds: receipt.sourceEvidenceIds,
      signalEvidenceSha256: receipt.signalEvidenceSha256,
      usedNodeIds: receipt.usedNodeIds,
      ignoredNodeIds: receipt.ignoredNodeIds,
      matchedHazardNodeIds: receipt.matchedHazardNodeIds,
    });
    const auditMaterial = {
      id: receipt.influenceAuditRecordId,
      missionId: receipt.missionId,
      runId: receipt.runId,
      journey: "autonomous",
      actorType: "agent",
      actorId: "autonomous-web-memory-guard",
      action: "brain.web_phase_memory_guard.compiled",
      resourceType: "web_phase_memory_guard",
      resourceId: receipt.receiptId,
      reason: receipt.decision === "block_endpoint_discovery"
        ? "Verified technology-specific hang or crash memory blocked endpoint discovery before authorization"
        : "The bounded Context Pack did not contain a verified applicable hang or crash guard",
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt: receipt.createdAt,
    };
    database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, 'autonomous-web-memory-guard', ?)
    `).run(key, canonicalJson(receipt), receipt.createdAt);
    database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, ?, ?, 'autonomous', 'agent', 'autonomous-web-memory-guard',
        'brain.web_phase_memory_guard.compiled', 'web_phase_memory_guard', ?, ?, ?, ?, ?, ?)
    `).run(
      receipt.influenceAuditRecordId,
      receipt.missionId,
      receipt.runId,
      receipt.receiptId,
      auditMaterial.reason,
      canonicalJson(details),
      previous?.record_hash ?? null,
      hashCanonical(auditMaterial),
      receipt.createdAt,
    );
    return receipt;
  });
}

/**
 * Compiles a non-generative, fail-closed influence receipt. Memory text can
 * never add scope or authorize contact; only exact typed node/profile links
 * and a verified local technology fingerprint may stop endpoint discovery.
 */
export function compileAutonomousWebPhaseMemoryGuard(input: Readonly<{
  database: SqliteDatabase;
  action: DurableAction;
  phase: AutonomousWebSurfacePhase;
  context: BrainContextResult;
  evidence: AutonomousWebPhaseMemoryEvidence;
  now?: Date;
}>): WebPhaseMemoryGuardReceipt {
  const now = input.now ?? new Date();
  const eligible = canonicalEligibleNodes(
    input.database,
    input.action,
    input.context,
    now,
  );
  const hazardIds = [...eligible.values()]
    .filter((node) => node.nodeType === "operational_hazard"
      && node.lifecycleStatus === "verified")
    .map(({ id }) => id).sort();
  const profiles = hazardIds.length === 0 ? [] : input.database.prepare(`
    SELECT node_id, product_node_ids_json, version_node_ids_json,
      stack_node_ids_json, observed_symptom, reproducibility_count,
      receipt_backed_occurrence_count, recovery_pattern_node_id,
      confidence, fresh_until
    FROM operational_hazard_profiles
    WHERE node_id IN (${hazardIds.map(() => "?").join(",")})
    ORDER BY node_id
  `).all(...hazardIds) as HazardProfileRow[];

  const matchedTechnology = new Set<string>();
  const matchedVersions = new Set<string>();
  const matchedHazards = new Set<string>();
  const matchedRecoveries = new Set<string>();
  if (input.phase === "endpoint_discovery" && input.evidence.technologySignals.length > 0) {
    for (const profile of profiles) {
      if (!HANG_OR_CRASH.test(profile.observed_symptom)
        || profile.confidence < VERIFIED_BLOCK_CONFIDENCE
        || (profile.receipt_backed_occurrence_count < 1
          && profile.reproducibility_count < MINIMUM_REPRODUCIBILITY_COUNT)
        || !activeAt(profile.fresh_until, now)) continue;
      const productIds = ids(profile.product_node_ids_json, `Hazard ${profile.node_id} products`);
      const versionIds = ids(profile.version_node_ids_json, `Hazard ${profile.node_id} versions`);
      if (productIds.length === 0 || versionIds.length === 0) continue;
      const products = productIds.map((id) => eligible.get(id));
      const versions = versionIds.map((id) => eligible.get(id));
      if (products.some((node) => !node || node.nodeType !== "technology_product")
        || versions.some((node) => !node || !VERSION_TYPES.has(node.nodeType))) continue;
      const productsMatch = (products as MemoryNode[]).every((node) =>
        input.evidence.technologySignals.some((signal) => productMatchesSignal(node, signal)));
      const versionsMatch = (versions as MemoryNode[]).every((node) =>
        input.evidence.technologySignals.some((signal) => versionMatchesSignal(node, signal)));
      if (!productsMatch || !versionsMatch) continue;
      matchedHazards.add(profile.node_id);
      productIds.forEach((id) => matchedTechnology.add(id));
      versionIds.forEach((id) => matchedVersions.add(id));
      for (const stackId of ids(profile.stack_node_ids_json, `Hazard ${profile.node_id} stack`)) {
        const node = eligible.get(stackId);
        if (node && TECHNOLOGY_TYPES.has(node.nodeType)
          && input.evidence.technologySignals.some((signal) =>
            productMatchesSignal(node, signal) && versionMatchesSignal(node, signal))) {
          matchedTechnology.add(stackId);
        }
      }
      if (profile.recovery_pattern_node_id) {
        const recovery = eligible.get(profile.recovery_pattern_node_id);
        if (recovery && RECOVERY_TYPES.has(recovery.nodeType)) {
          matchedRecoveries.add(recovery.id);
        }
      }
    }
  }
  const usedNodeIds = Object.freeze([...new Set([
    ...matchedTechnology,
    ...matchedVersions,
    ...matchedHazards,
    ...matchedRecoveries,
  ])].sort());
  const allNodeIds = Object.freeze([...new Set(input.context.items.map(({ node }) => node.id))].sort());
  const ignoredNodeIds = Object.freeze(allNodeIds.filter((id) => !usedNodeIds.includes(id)));
  const decision: AutonomousWebPhaseMemoryGuardDecision = matchedHazards.size > 0
    ? "block_endpoint_discovery" : "allow";
  const reasonCode = decision === "block_endpoint_discovery"
    ? "verified_hang_or_crash_hazard_match" as const
    : allNodeIds.length === 0
      ? "no_relevant_memory" as const
      : "no_verified_technology_hazard_match" as const;
  const identity = createHash("sha256").update([
    input.action.id,
    input.action.fingerprint,
    input.context.contextPack.id,
    input.phase,
  ].join("\u0000"), "utf8").digest("hex");
  const receiptId = `web_memory_guard_${identity.slice(0, 40)}`;
  const influenceAuditRecordId = `audit_web_memory_guard_${identity.slice(0, 40)}`;
  return persistReceipt(input.database, Object.freeze({
    schemaVersion: AUTONOMOUS_WEB_PHASE_MEMORY_GUARD_SCHEMA_VERSION,
    receiptId,
    missionId: input.action.missionId,
    runId: input.action.runId,
    actionId: input.action.id,
    actionFingerprint: input.action.fingerprint,
    phase: input.phase,
    contextPackId: input.context.contextPack.id,
    contextRetrievalAuditRecordId: input.context.auditRecordId,
    influenceAuditRecordId,
    sourceEvidenceIds: Object.freeze([...input.evidence.sourceEvidenceIds]),
    signalEvidenceSha256: input.evidence.signalEvidenceSha256,
    matchedTechnologyNodeIds: Object.freeze([...matchedTechnology].sort()),
    matchedVersionNodeIds: Object.freeze([...matchedVersions].sort()),
    matchedHazardNodeIds: Object.freeze([...matchedHazards].sort()),
    matchedRecoveryNodeIds: Object.freeze([...matchedRecoveries].sort()),
    usedNodeIds,
    ignoredNodeIds,
    decision,
    reasonCode,
    createdAt: now.toISOString(),
  }));
}
