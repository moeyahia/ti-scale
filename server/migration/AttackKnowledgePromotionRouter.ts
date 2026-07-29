import { createHash } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { canonicalJson } from "../orchestration/serialization";
import {
  AttackKnowledgePromotionError,
  AttackKnowledgePromotionService,
  type AttackKnowledgePromotionResult,
} from "./AttackKnowledgePromotionService";

const SCHEMA_VERSION = "2.4" as const;
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9._:@/-]{1,300}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const REVIEWED_CANDIDATE_STATUSES = new Set(["confirmed", "edited_confirmed", "merged"]);

export interface AttackKnowledgePromotionActor {
  readonly id: string;
  readonly type: "operator" | "reviewer" | "admin";
}

export interface AttackKnowledgePromotionRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => AttackKnowledgePromotionActor | undefined;
  /** Explicit server-owned policy. This API never infers operator authority from request fields. */
  readonly authorize: (
    request: Request,
    actor: AttackKnowledgePromotionActor,
    operation: "list" | "review" | "promote",
  ) => boolean;
  /** Private evidence remains inaccessible unless the mounted application authorizes its sensitivity. */
  readonly authorizeEvidence: (
    request: Request,
    actor: AttackKnowledgePromotionActor,
    evidence: { readonly id: string; readonly sensitivity: string },
  ) => boolean;
}

interface BundleRow {
  readonly id: string;
  readonly semantic_fingerprint: string;
  readonly sanitized_bundle_json: string;
  readonly status: "staged" | "materialized";
  readonly exact_procedure_attempt_count: number;
  readonly exact_procedure_reproducibility_count: number;
  readonly exact_procedure_evidence_count: number;
  readonly exact_procedure_reset_count: number;
  readonly operator_reported_reset_count_minimum: number | null;
  readonly first_observed_at: string;
  readonly last_observed_at: string;
}

interface BoundEvidenceRow {
  readonly id: string;
  readonly content_hash: string;
  readonly bound_content_hash: string;
  readonly evidence_type: string;
  readonly acquired_at: string;
  readonly bound_acquired_at: string;
  readonly verification_state: string;
  readonly sensitivity: string;
  readonly canonical_verified: number;
}

class PromotionApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly humanMessage: string,
    readonly category: string,
    readonly remediation?: string,
    readonly details?: unknown,
  ) {
    super(humanMessage);
    this.name = "PromotionApiError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PromotionApiError(400, "promotion_invalid_request", `${label} must be a JSON object`, "invalid_input");
  }
  return value as Record<string, unknown>;
}

function exactObject(value: unknown, allowed: readonly string[], label: string): Record<string, unknown> {
  const result = object(value, label);
  const extras = Object.keys(result).filter((key) => !allowed.includes(key));
  if (extras.length > 0) {
    throw new PromotionApiError(400, "promotion_invalid_request", `${label} contains unsupported fields`, "invalid_input");
  }
  return result;
}

function fingerprint(value: unknown): string {
  const result = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!SHA256.test(result)) {
    throw new PromotionApiError(400, "promotion_invalid_request", "Bundle fingerprint must be a lowercase SHA-256 digest", "invalid_input");
  }
  return result;
}

function evidenceIds(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > 100) {
    throw new PromotionApiError(400, "promotion_invalid_request", "Evidence selection must contain at most 100 IDs", "invalid_input");
  }
  const result = value.map((candidate) => {
    const id = typeof candidate === "string" ? candidate.trim() : "";
    if (!SAFE_ID.test(id)) throw new PromotionApiError(400, "promotion_invalid_request", "Evidence selection contains an invalid ID", "invalid_input");
    return id;
  }).sort();
  if (new Set(result).size !== result.length) {
    throw new PromotionApiError(400, "promotion_invalid_request", "Evidence selection contains duplicate IDs", "invalid_input");
  }
  return result;
}

function requireActor(
  request: Request,
  dependencies: AttackKnowledgePromotionRouterDependencies,
  operation: "list" | "review" | "promote",
): AttackKnowledgePromotionActor {
  const actor = dependencies.resolveActor(request);
  if (!actor?.id.trim()) {
    throw new PromotionApiError(401, "promotion_authentication_required", "An authenticated operator identity is required", "authentication_missing");
  }
  if (actor.type !== "operator" || !dependencies.authorize(request, actor, operation)) {
    throw new PromotionApiError(
      403,
      "promotion_operator_required",
      "Only an authenticated operator may review or promote reusable attack knowledge",
      "policy_denied",
      "Sign in with an operator session. Agents, reviewers, and providers cannot promote their own candidates.",
    );
  }
  return { ...actor, id: actor.id.trim() };
}

function requireBundle(database: SqliteDatabase, bundleFingerprint: string): BundleRow {
  const row = database.prepare(`
    SELECT id, semantic_fingerprint, sanitized_bundle_json, status,
      exact_procedure_attempt_count, exact_procedure_reproducibility_count,
      exact_procedure_evidence_count, exact_procedure_reset_count,
      operator_reported_reset_count_minimum, first_observed_at, last_observed_at
    FROM attack_knowledge_bundles WHERE semantic_fingerprint = ?
  `).get(bundleFingerprint) as BundleRow | undefined;
  if (!row) throw new PromotionApiError(404, "promotion_bundle_not_found", "The staged attack-knowledge bundle was not found", "not_found");
  return row;
}

function bundleKind(row: BundleRow): "operational_hazard" | "reusable_fact" | "reusable_bundle" {
  let value: unknown;
  try {
    value = (JSON.parse(row.sanitized_bundle_json) as { knowledge?: { kind?: unknown } }).knowledge?.kind;
  } catch {
    throw new PromotionApiError(500, "promotion_integrity_mismatch", "The staged bundle failed its integrity check", "data_integrity");
  }
  if (value !== "operational_hazard" && value !== "reusable_fact" && value !== "reusable_bundle") {
    throw new PromotionApiError(500, "promotion_integrity_mismatch", "The staged bundle has an unsupported knowledge kind", "data_integrity");
  }
  return value;
}

function boundEvidence(database: SqliteDatabase, bundle: BundleRow): readonly BoundEvidenceRow[] {
  const rows = database.prepare(`
    SELECT e.id, e.content_hash, binding.content_hash AS bound_content_hash,
      e.evidence_type, e.acquired_at, binding.acquired_at AS bound_acquired_at,
      e.verification_state, e.sensitivity,
      CASE WHEN (${verifiedEvidenceSql("e")}) AND EXISTS (
        SELECT 1 FROM evidence_chain_events custody
        WHERE custody.evidence_id = e.id AND custody.event_type = 'verified'
      ) THEN 1 ELSE 0 END AS canonical_verified
    FROM attack_knowledge_bundle_evidence_bindings binding
    JOIN evidence e ON e.id = binding.evidence_id
    WHERE binding.bundle_id = ? ORDER BY e.acquired_at, e.id
  `).all(bundle.id) as BoundEvidenceRow[];
  if (rows.some((row) =>
    row.canonical_verified !== 1
    || row.verification_state !== "verified"
    || row.content_hash !== row.bound_content_hash
    || row.acquired_at !== row.bound_acquired_at
    || !SHA256.test(row.content_hash)
  )) {
    throw new PromotionApiError(
      500,
      "promotion_evidence_integrity_mismatch",
      "A bundle-linked evidence record no longer matches its immutable compiler binding",
      "data_integrity",
      "Inspect the local evidence custody chain and compiler receipt. Do not promote this bundle.",
    );
  }
  return rows;
}

function authorizeBoundEvidence(
  request: Request,
  actor: AttackKnowledgePromotionActor,
  dependencies: AttackKnowledgePromotionRouterDependencies,
  rows: readonly BoundEvidenceRow[],
): void {
  if (rows.some((row) => !dependencies.authorizeEvidence(request, actor, { id: row.id, sensitivity: row.sensitivity }))) {
    // Do not reveal which private evidence row was outside the actor's access.
    throw new PromotionApiError(404, "promotion_bundle_not_found", "The staged attack-knowledge bundle was not found", "not_found");
  }
}

function assertSelectionIsBound(selectedIds: readonly string[], rows: readonly BoundEvidenceRow[]): void {
  const allowed = new Set(rows.map((row) => row.id));
  if (selectedIds.some((id) => !allowed.has(id))) {
    throw new PromotionApiError(
      400,
      "promotion_evidence_not_bound",
      "The evidence selection contains an item that was not immutably bound to this bundle by the compiler",
      "invalid_input",
      "Refresh the bundle and select only evidence offered by this review surface.",
    );
  }
}

function normalizedServiceError(error: AttackKnowledgePromotionError): PromotionApiError {
  const status = error.code === "promotion_bundle_not_found" ? 404
    : error.code === "promotion_invalid_request" ? 400
      : error.code === "promotion_integrity_mismatch" ? 500
        : 409;
  return new PromotionApiError(
    status,
    error.code,
    error.message,
    status === 500 ? "data_integrity" : status === 404 ? "not_found" : status === 400 ? "invalid_input" : "conflict",
    error.code === "promotion_stale_review"
      ? "Refresh the bundle, rebuild the preview, and review the new hash before deciding again."
      : error.code === "promotion_not_ready"
        ? "Resolve every listed blocker and rebuild the exact preview."
        : undefined,
    error.blockers.length > 0 ? { blockers: error.blockers } : undefined,
  );
}

function sendError(response: Response, error: unknown, traceId: string): void {
  const normalized = error instanceof PromotionApiError
    ? error
    : error instanceof AttackKnowledgePromotionError
      ? normalizedServiceError(error)
      : new PromotionApiError(500, "promotion_internal_error", "Attack-knowledge promotion could not complete safely", "internal");
  sendV2Error(response, traceId, {
    status: normalized.status,
    code: normalized.code,
    message: normalized.message,
    humanMessage: normalized.humanMessage,
    retryable: false,
    category: normalized.category,
    ...(normalized.remediation ? { remediation: normalized.remediation } : {}),
    ...(normalized.details === undefined ? {} : { details: normalized.details }),
  });
}

function promotionIdempotencyKey(request: Request): string {
  const key = request.get("Idempotency-Key")?.trim() ?? "";
  if (!IDEMPOTENCY_KEY.test(key)) {
    throw new PromotionApiError(
      400,
      "idempotency_key_required",
      "A stable 8-200 character Idempotency-Key is required for promotion",
      "invalid_input",
      "Reuse the same key only when retrying this exact reviewed hash and evidence set.",
    );
  }
  return key;
}

function promoteIdempotently(
  database: SqliteDatabase,
  service: AttackKnowledgePromotionService,
  actor: AttackKnowledgePromotionActor,
  key: string,
  input: {
    readonly bundleFingerprint: string;
    readonly expectedReviewHash: string;
    readonly verificationEvidenceIds: readonly string[];
  },
): AttackKnowledgePromotionResult {
  const settingKey = `idempotency.attack-knowledge-promotion.${sha256(`${actor.id}:${key}`)}`;
  const requestHash = sha256(canonicalJson(input));
  const existing = database.prepare("SELECT value_json FROM settings WHERE key = ?")
    .get(settingKey) as { readonly value_json: string } | undefined;
  if (existing) {
    const stored = JSON.parse(existing.value_json) as { readonly requestHash?: string; readonly response?: AttackKnowledgePromotionResult };
    if (stored.requestHash !== requestHash || !stored.response) {
      throw new PromotionApiError(409, "idempotency_key_reused", "This idempotency key was used for a different promotion decision", "conflict", "Use a new key after changing the bundle, evidence selection, or review hash.");
    }
    return stored.response;
  }

  const result = service.promote({ ...input, actor: actor.id });
  inImmediateTransaction(database, () => {
    const raced = database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(settingKey) as { readonly value_json: string } | undefined;
    if (raced) {
      const stored = JSON.parse(raced.value_json) as { readonly requestHash?: string };
      if (stored.requestHash !== requestHash) {
        throw new PromotionApiError(409, "idempotency_key_reused", "This idempotency key was used for a different promotion decision", "conflict");
      }
      return;
    }
    database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, updated_by, updated_at)
      VALUES (?, ?, 'private', ?, ?)
    `).run(
      settingKey,
      canonicalJson({ requestHash, response: result }),
      actor.id,
      new Date().toISOString(),
    );
  });
  return result;
}

function listBundles(database: SqliteDatabase, status: unknown) {
  const normalized = status === undefined ? "staged" : String(status);
  if (!new Set(["staged", "materialized", "all"]).has(normalized)) {
    throw new PromotionApiError(400, "promotion_invalid_filter", "Bundle status must be staged, materialized, or all", "invalid_input");
  }
  const rows = database.prepare(`
    SELECT id, semantic_fingerprint, sanitized_bundle_json, status,
      exact_procedure_attempt_count, exact_procedure_reproducibility_count,
      exact_procedure_evidence_count, exact_procedure_reset_count,
      operator_reported_reset_count_minimum, first_observed_at, last_observed_at
    FROM attack_knowledge_bundles
    WHERE (? = 'all' OR status = ?)
    ORDER BY CASE status WHEN 'staged' THEN 0 ELSE 1 END, updated_at DESC, id
    LIMIT 100
  `).all(normalized, normalized) as BundleRow[];
  const items = rows.map((row) => {
    const candidates = database.prepare(`
      SELECT candidate.status
      FROM attack_knowledge_bundle_candidates linked
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = linked.content_fingerprint
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      WHERE linked.bundle_id = ?
    `).all(row.id) as Array<{ readonly status: string }>;
    const receipt = database.prepare(`
      SELECT id, review_hash, audit_record_id, promoted_at
      FROM attack_knowledge_promotion_receipts
      WHERE bundle_id = ? ORDER BY promotion_sequence DESC LIMIT 1
    `).get(row.id) as { readonly id: string; readonly review_hash: string; readonly audit_record_id: string; readonly promoted_at: string } | undefined;
    const boundCount = Number((database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_evidence_bindings WHERE bundle_id = ?
    `).get(row.id) as { readonly count: number }).count);
    return {
      bundleId: row.id,
      bundleFingerprint: row.semantic_fingerprint,
      status: row.status,
      kind: bundleKind(row),
      candidates: {
        total: candidates.length,
        reviewed: candidates.filter(({ status: candidateStatus }) => REVIEWED_CANDIDATE_STATUSES.has(candidateStatus)).length,
        pending: candidates.filter(({ status: candidateStatus }) => candidateStatus === "pending").length,
        rejected: candidates.filter(({ status: candidateStatus }) => candidateStatus === "rejected" || candidateStatus === "suppressed").length,
      },
      exactProcedureCounts: {
        attempts: Number(row.exact_procedure_attempt_count),
        reproducibleOutcomes: Number(row.exact_procedure_reproducibility_count),
        evidenceItems: Number(row.exact_procedure_evidence_count),
        exactResets: Number(row.exact_procedure_reset_count),
        operatorReportedAggregateResetMinimum: row.operator_reported_reset_count_minimum === null
          ? null
          : Number(row.operator_reported_reset_count_minimum),
      },
      boundEvidenceCount: boundCount,
      firstObservedAt: row.first_observed_at,
      lastObservedAt: row.last_observed_at,
      promotedReceipt: receipt ? {
        id: receipt.id,
        reviewHash: receipt.review_hash,
        auditRecordId: receipt.audit_record_id,
        promotedAt: receipt.promoted_at,
      } : null,
    };
  });
  return { schemaVersion: SCHEMA_VERSION, items, totalReturned: items.length };
}

/** Authenticated, operator-only bridge from staged compiler output to immutable reusable knowledge. */
export function createAttackKnowledgePromotionRouter(
  dependencies: AttackKnowledgePromotionRouterDependencies,
): Router {
  const router = Router();
  const promotion = new AttackKnowledgePromotionService(dependencies.database);

  router.use("/api/v2/brain/attack-knowledge", (_request, response, next) => {
    response.setHeader("Cache-Control", "private, no-store");
    next();
  });

  router.get("/api/v2/brain/attack-knowledge/bundles", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      requireActor(request, dependencies, "list");
      response.json(listBundles(dependencies.database, request.query.status));
    } catch (error) { sendError(response, error, traceId); }
  });

  router.get("/api/v2/brain/attack-knowledge/bundles/:fingerprint/evidence", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = requireActor(request, dependencies, "review");
      const normalizedFingerprint = fingerprint(request.params.fingerprint);
      const bundle = requireBundle(dependencies.database, normalizedFingerprint);
      const rows = boundEvidence(dependencies.database, bundle);
      authorizeBoundEvidence(request, actor, dependencies, rows);
      response.json({
        schemaVersion: SCHEMA_VERSION,
        bundleId: bundle.id,
        bundleFingerprint: bundle.semantic_fingerprint,
        items: rows.map((row) => ({
          id: row.id,
          contentHash: row.content_hash,
          evidenceType: row.evidence_type,
          acquiredAt: row.acquired_at,
          verificationState: "verified" as const,
        })),
        totalReturned: rows.length,
      });
    } catch (error) { sendError(response, error, traceId); }
  });

  router.post("/api/v2/brain/attack-knowledge/bundles/:fingerprint/preview", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = requireActor(request, dependencies, "review");
      const normalizedFingerprint = fingerprint(request.params.fingerprint);
      const input = exactObject(request.body, ["verificationEvidenceIds"], "Promotion preview");
      const selectedIds = evidenceIds(input.verificationEvidenceIds);
      const bundle = requireBundle(dependencies.database, normalizedFingerprint);
      const rows = boundEvidence(dependencies.database, bundle);
      authorizeBoundEvidence(request, actor, dependencies, rows);
      assertSelectionIsBound(selectedIds, rows);
      response.json({ schemaVersion: SCHEMA_VERSION, ...promotion.preview(normalizedFingerprint, selectedIds) });
    } catch (error) { sendError(response, error, traceId); }
  });

  router.post("/api/v2/brain/attack-knowledge/bundles/:fingerprint/promote", (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const actor = requireActor(request, dependencies, "promote");
      const key = promotionIdempotencyKey(request);
      const normalizedFingerprint = fingerprint(request.params.fingerprint);
      const input = exactObject(request.body, ["expectedReviewHash", "verificationEvidenceIds"], "Promotion decision");
      const expectedReviewHash = fingerprint(input.expectedReviewHash);
      const selectedIds = evidenceIds(input.verificationEvidenceIds);
      const bundle = requireBundle(dependencies.database, normalizedFingerprint);
      const rows = boundEvidence(dependencies.database, bundle);
      authorizeBoundEvidence(request, actor, dependencies, rows);
      assertSelectionIsBound(selectedIds, rows);
      const result = promoteIdempotently(dependencies.database, promotion, actor, key, {
        bundleFingerprint: normalizedFingerprint,
        expectedReviewHash,
        verificationEvidenceIds: selectedIds,
      });
      response.json({ schemaVersion: SCHEMA_VERSION, ...result });
    } catch (error) { sendError(response, error, traceId); }
  });

  return router;
}
