import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { basename, extname, isAbsolute, normalize } from "node:path";
import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import { digestCanonicalJson } from "../mcp";
import {
  assertNoEmbeddedSecrets,
  type ScriptArtifactDetail,
  type ScriptArtifactService,
  type ScriptExpectedOutput,
  type ScriptLanguage,
  type ScriptParameter,
  type ScriptRiskClass,
  type ScriptTestRecord,
  type ScriptTouches,
} from "../script-artifacts";
import { REVIEWED_PYTHON_INTERPRETER_BINDING_ID } from "../exploit-sandbox/types";
import type {
  ConnectedVaultMemoryProjector,
  ConnectedVaultProjectionReport,
} from "../vault/ConnectedVaultMemoryProjector";

const SHA256 = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9._:@-]{1,240}$/u;
const MAX_SOURCE_BYTES = 512 * 1024;
const REQUIRED_EDGE_BINDINGS = Object.freeze([
  ["procedure", "implemented_by", "script"],
  ["procedure", "exploits", "cve"],
  ["procedure", "tested_against", "product"],
  ["procedure", "tested_against", "version"],
  ["product", "has_exact_version", "version"],
  ["cve", "affects", "product"],
  ["cve", "affects", "version"],
] as const);

export const HISTORICAL_EXECUTABLE_SCRIPT_PREVIEW_SCHEMA =
  "ti-scale.historical-executable-script-promotion-preview.v1" as const;
export const HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_SCHEMA =
  "ti-scale.historical-executable-script-validation.v1" as const;
export const HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_RECEIPT_SCHEMA =
  "ti-scale.historical-executable-script-validation-receipt.v1" as const;
export const HISTORICAL_EXECUTABLE_SCRIPT_PROMOTION_SCHEMA =
  "ti-scale.historical-executable-script-promotion.v1" as const;

export interface HistoricalExecutableScriptSelection {
  readonly bundleId: string;
  readonly sourceCandidateId: string;
  readonly migrationId: string;
  readonly sourceReference: string;
  readonly expectedSourceHash: string;
  readonly scriptNodeId: string;
  readonly procedureNodeId: string;
  readonly productNodeId: string;
  readonly versionNodeId: string;
  readonly cveNodeId: string;
}

export interface HistoricalExecutableScriptDocumentation {
  readonly name: string;
  readonly language: ScriptLanguage;
  readonly laymanExplanation: string;
  readonly technicalPurpose: string;
  readonly inputs: readonly ScriptParameter[];
  readonly expectedOutputs: readonly ScriptExpectedOutput[];
  readonly prerequisites: readonly string[];
  readonly dependencies: readonly string[];
  readonly touches: ScriptTouches;
  readonly sideEffects: readonly string[];
  readonly riskClass: Extract<ScriptRiskClass, "low" | "medium">;
  readonly reversibility: string;
  readonly cleanupNotes: string;
  readonly secretsHandling: string;
  readonly evidenceExpectations: readonly string[];
  readonly sensitivity: "internal" | "private";
}

export interface HistoricalExecutableScriptPromotionInput {
  readonly actorId: string;
  readonly reason: string;
  readonly selection: HistoricalExecutableScriptSelection;
  readonly documentation: HistoricalExecutableScriptDocumentation;
}

export interface HistoricalExecutableScriptPromotionFence {
  readonly expectedPreviewHash: string;
  readonly expectedSourceHash: string;
  readonly reviewedExactSourceAndBindings: true;
  readonly acknowledgedNoAutomaticExecution: true;
}

export interface HistoricalExecutableScriptValidationRequest {
  readonly schemaVersion: typeof HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_SCHEMA;
  readonly bundleId: string;
  readonly migrationId: string;
  readonly sourceCandidateId: string;
  readonly sourceReference: string;
  readonly sourceHash: string;
  readonly source: string;
  readonly language: ScriptLanguage;
  readonly publicProvider: false;
  readonly targetContact: false;
  readonly sourceExecution: false;
}

export interface HistoricalExecutableScriptValidationReceipt {
  readonly schemaVersion: typeof HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_RECEIPT_SCHEMA;
  readonly receiptId: string;
  readonly bundleId: string;
  readonly migrationId: string;
  readonly sourceCandidateId: string;
  readonly sourceHash: string;
  readonly language: ScriptLanguage;
  readonly validatorBindingId: string;
  readonly tests: readonly ScriptTestRecord[];
  readonly publicProvider: false;
  readonly targetContact: false;
  readonly sourceExecution: false;
  readonly isolatedLocalValidation: true;
  readonly validatedAt: string;
  readonly receiptHash: string;
}

export interface HistoricalExecutableScriptValidationPort {
  validate(
    request: HistoricalExecutableScriptValidationRequest,
  ): Promise<HistoricalExecutableScriptValidationReceipt>;
}

export interface HistoricalExecutableScriptPromotionPreview {
  readonly schemaVersion: typeof HISTORICAL_EXECUTABLE_SCRIPT_PREVIEW_SCHEMA;
  readonly destinationMissionId: string;
  readonly destinationRunId: string;
  readonly canonicalName: string;
  readonly sourceHash: string;
  readonly sourceByteSize: number;
  /** Returned only to the authenticated local operator for explicit code review. */
  readonly source: string;
  readonly sourceReference: string;
  readonly bundleId: string;
  readonly sourceCandidateId: string;
  readonly nodeBindings: Readonly<{
    script: { readonly id: string; readonly title: string };
    procedure: { readonly id: string; readonly title: string };
    product: { readonly id: string; readonly title: string };
    version: { readonly id: string; readonly title: string };
    cve: { readonly id: string; readonly title: string };
  }>;
  readonly successfulAttemptId: string;
  readonly successEvidenceId: string;
  readonly sourceVerificationEvidenceId: string;
  readonly documentation: HistoricalExecutableScriptDocumentation;
  readonly executableByCurrentRuntime: true;
  readonly runtimeBindingId: typeof REVIEWED_PYTHON_INTERPRETER_BINDING_ID;
  readonly publicProvider: false;
  readonly targetContact: false;
  readonly sourceExecution: false;
  readonly previewHash: string;
}

export interface HistoricalExecutableScriptPromotionResult {
  readonly schemaVersion: typeof HISTORICAL_EXECUTABLE_SCRIPT_PROMOTION_SCHEMA;
  readonly status: "promoted" | "replayed";
  readonly scriptArtifact: ScriptArtifactDetail;
  readonly validationArtifactId: string;
  readonly validationReceiptId: string;
  readonly validationReceiptHash: string;
  readonly promotionAuditId: string;
  readonly provenanceSourceId: string;
  readonly provenanceAuditId: string;
  readonly previewHash: string;
  readonly vaultProjection: ConnectedVaultProjectionReport & Readonly<{
    readonly complete: boolean;
    readonly auditId: string;
  }>;
  readonly publicProvider: false;
  readonly targetContactDuringPromotion: false;
  readonly sourceExecutedDuringPromotion: false;
}

export interface HistoricalExecutableScriptEligibilityEntry {
  readonly selection: HistoricalExecutableScriptSelection;
  readonly language: string;
  readonly scriptTitle: string;
  readonly procedureTitle: string;
  readonly productTitle: string;
  readonly versionTitle: string;
  readonly cveTitle: string;
  readonly successfulAttemptId: string;
  readonly successEvidenceId: string;
  readonly executableByCurrentRuntime: boolean;
}

export interface HistoricalExecutableScriptCustodyEntry {
  readonly scriptNodeId: string;
  readonly scriptTitle: string;
  readonly language: string;
  readonly sourceHash: string;
  readonly executableByCurrentRuntime: boolean;
  readonly exactBoundVerifiedSuccessEligible: boolean;
  readonly reasonCategories: readonly string[];
}

export interface HistoricalExecutableScriptEligibilityReport {
  readonly schemaVersion: "ti-scale.historical-executable-script-eligibility.v1";
  readonly historicalScriptNodeCount: number;
  readonly languageCounts: Readonly<Record<string, number>>;
  readonly exactBoundVerifiedSuccessCount: number;
  readonly executableByCurrentRuntimeCount: number;
  /**
   * Read-only custody inventory, including sources that correctly remain
   * ineligible because an exact same-bundle success binding is absent.
   */
  readonly custodiedScripts: readonly HistoricalExecutableScriptCustodyEntry[];
  readonly entries: readonly HistoricalExecutableScriptEligibilityEntry[];
  readonly generatedAt: string;
}

export class HistoricalExecutableScriptPromotionError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "HistoricalExecutableScriptPromotionError";
  }
}

interface NodeRow {
  readonly id: string;
  readonly node_type: string;
  readonly title: string;
  readonly body: string;
}

interface SourceRow {
  readonly source_path: string;
  readonly source_hash: string;
  readonly byte_size: number;
  readonly source_device: number;
  readonly source_inode: number;
  readonly verification_evidence_id: string;
  readonly destination_mission_id: string;
  readonly destination_run_id: string;
}

interface SuccessRow {
  readonly attack_attempt_id: string;
  readonly evidence_id: string;
}

type PersistedPromotionResult = Omit<
  HistoricalExecutableScriptPromotionResult,
  "provenanceSourceId" | "provenanceAuditId" | "vaultProjection"
>;

type ProvenanceBoundPromotionResult = PersistedPromotionResult & Readonly<{
  provenanceSourceId: string;
  provenanceAuditId: string;
}>;

interface ProvenanceBinding {
  readonly sourceId: string;
  readonly auditId: string;
}

function fail(code: string, message: string): never {
  throw new HistoricalExecutableScriptPromotionError(code, message);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stableId(prefix: string, values: readonly string[]): string {
  return `${prefix}_${sha256(values.join("\u0000")).slice(0, 48)}`;
}

function parseBody(body: string): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(body) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Readonly<Record<string, unknown>>
      : {};
  } catch {
    return {};
  }
}

function receiptMaterial(
  receipt: HistoricalExecutableScriptValidationReceipt,
): Omit<HistoricalExecutableScriptValidationReceipt, "receiptHash"> {
  const { receiptHash: _receiptHash, ...material } = receipt;
  return material;
}

function canonicalName(sourceHash: string, reviewedName: string): string {
  return `historical/${sourceHash.slice(0, 16)}/${basename(reviewedName)}`;
}

function normalizedInput(
  input: HistoricalExecutableScriptPromotionInput,
): HistoricalExecutableScriptPromotionInput {
  if (!IDENTIFIER.test(input.actorId.trim())) {
    fail("historical_script_operator_required", "A bounded operator actor ID is required.");
  }
  if (input.reason.trim().length < 12 || input.reason.trim().length > 1_200) {
    fail("historical_script_review_reason_required", "An operator review reason between 12 and 1200 characters is required.");
  }
  const selectionValues = Object.values(input.selection);
  if (selectionValues.some((value) => typeof value !== "string" || value.trim().length === 0)) {
    fail("historical_script_selection_invalid", "Every exact historical source and graph binding must be selected.");
  }
  if (!SHA256.test(input.selection.expectedSourceHash)) {
    fail("historical_script_source_hash_invalid", "The reviewed source hash must be a lowercase SHA-256 digest.");
  }
  if (!input.selection.sourceReference.startsWith("legacy-private-source://")) {
    fail("historical_script_source_reference_invalid", "Promotion requires an opaque verified historical source reference.");
  }
  const documentation = input.documentation;
  if (documentation.language !== "python") {
    fail(
      "historical_script_runtime_binding_unavailable",
      "The current production execution gate supports only the reviewed Python interpreter binding; this source remains historical custody.",
    );
  }
  if (!["low", "medium"].includes(documentation.riskClass)) {
    fail("historical_script_risk_not_bounded", "Historical executable promotion is limited to low- or medium-risk reviewed source.");
  }
  if (!["internal", "private"].includes(documentation.sensitivity)) {
    fail("historical_script_sensitivity_invalid", "Historical executable source must remain internal or private.");
  }
  if (
    documentation.inputs.some(({ sensitivity }) => sensitivity !== "ordinary")
    || !documentation.inputs.some(({ name, required }) => name === "target" && required)
  ) {
    fail("historical_script_input_boundary_invalid", "The reviewed script must use one required ordinary target parameter and no secret inputs.");
  }
  if (documentation.touches.files.length > 0 || documentation.touches.services.length > 0) {
    fail("historical_script_side_effect_boundary_invalid", "P0 reusable promotion cannot approve file or service mutation.");
  }
  return {
    ...input,
    actorId: input.actorId.trim(),
    reason: input.reason.trim(),
    documentation: {
      ...documentation,
      name: documentation.name.trim(),
    },
  };
}

/**
 * Explicit, operator-fenced conversion of verified historical source custody
 * into a canonical immutable ScriptArtifact.
 *
 * This service never runs historical source, contacts a target, or calls a
 * model/provider. It permits only byte-identical promotion from one verified
 * same-bundle product/version/CVE/procedure/script graph whose procedure has a
 * canonical prior successful AttackAttempt with verified evidence.
 */
export class HistoricalExecutableScriptPromotionService {
  readonly #audit: AuditTrailWriter;
  readonly #clock: () => Date;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    scripts: ScriptArtifactService;
    validator: HistoricalExecutableScriptValidationPort;
    vaultProjector?: Pick<ConnectedVaultMemoryProjector, "project">;
    clock?: () => Date;
  }>) {
    this.#audit = new AuditTrailWriter(options.database);
    this.#clock = options.clock ?? (() => new Date());
  }

  /**
   * Read-only production inventory. Entries have all canonical graph, custody,
   * and prior-success bindings, but source bytes and operator documentation
   * are still revalidated by `preview` before they can be promoted.
   */
  listEligibility(limit = 1_000): HistoricalExecutableScriptEligibilityReport {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      fail("historical_script_eligibility_limit_invalid", "Eligibility limit must be between 1 and 1000.");
    }
    const languageRows = this.options.database.prepare(`
      SELECT
        CASE
          WHEN json_valid(script.body)
            THEN lower(COALESCE(json_extract(script.body, '$.language'), 'unknown'))
          ELSE 'unknown'
        END AS language,
        COUNT(DISTINCT script.id) AS count
      FROM memory_nodes script
      JOIN memory_sources source
        ON source.node_id = script.id
       AND source.source_type =
         'historical_attack_knowledge_source_candidate'
      JOIN historical_private_source_bindings binding
        ON binding.memory_source_id = source.id
       AND binding.source_hash = source.source_hash
      WHERE script.node_type = 'script_artifact'
        AND script.scope = 'global'
        AND script.engagement_id IS NULL AND script.mission_id IS NULL
        AND script.lifecycle_status = 'verified'
        AND script.confirmation_state = 'confirmed'
      GROUP BY language
      ORDER BY language
    `).all() as Array<{ readonly language: string; readonly count: number }>;
    const custodyRows = this.options.database.prepare(`
      SELECT DISTINCT
        script.id AS script_node_id,
        script.title AS script_title,
        CASE
          WHEN json_valid(script.body)
            THEN lower(COALESCE(json_extract(script.body, '$.language'), 'unknown'))
          ELSE 'unknown'
        END AS language,
        source.source_hash
      FROM memory_nodes script
      JOIN memory_sources source
        ON source.node_id = script.id
       AND source.source_type =
         'historical_attack_knowledge_source_candidate'
      JOIN historical_private_source_bindings binding
        ON binding.memory_source_id = source.id
       AND binding.source_hash = source.source_hash
      WHERE script.node_type = 'script_artifact'
        AND script.scope = 'global'
        AND script.engagement_id IS NULL AND script.mission_id IS NULL
        AND script.lifecycle_status = 'verified'
        AND script.confirmation_state = 'confirmed'
      ORDER BY script.id, source.source_hash
      LIMIT ?
    `).all(limit) as Array<{
      readonly script_node_id: string;
      readonly script_title: string;
      readonly language: string;
      readonly source_hash: string;
    }>;
    const rows = this.options.database.prepare(`
      SELECT DISTINCT
        bundle.id AS bundle_id,
        occurrence.candidate_id AS source_candidate_id,
        occurrence.migration_id,
        occurrence.source_reference,
        occurrence.source_hash,
        script.id AS script_node_id,
        procedure.id AS procedure_node_id,
        product.id AS product_node_id,
        version.id AS version_node_id,
        cve.id AS cve_node_id,
        CASE
          WHEN json_valid(script.body)
            THEN lower(COALESCE(json_extract(script.body, '$.language'), 'unknown'))
          ELSE 'unknown'
        END AS language,
        script.title AS script_title,
        procedure.title AS procedure_title,
        product.title AS product_title,
        version.title AS version_title,
        cve.title AS cve_title,
        success.attack_attempt_id,
        success.evidence_id
      FROM attack_knowledge_bundles bundle
      JOIN memory_edges implementation
        ON implementation.edge_type = 'implemented_by'
       AND implementation.lifecycle_status = 'verified'
      JOIN memory_nodes procedure
        ON procedure.id = implementation.source_node_id
       AND procedure.node_type = 'attack_procedure'
      JOIN memory_nodes script
        ON script.id = implementation.target_node_id
       AND script.node_type = 'script_artifact'
      JOIN memory_edges exploitation
        ON exploitation.source_node_id = procedure.id
       AND exploitation.edge_type = 'exploits'
       AND exploitation.lifecycle_status = 'verified'
      JOIN memory_nodes cve
        ON cve.id = exploitation.target_node_id
       AND cve.node_type = 'cve'
      JOIN memory_edges tested_product
        ON tested_product.source_node_id = procedure.id
       AND tested_product.edge_type = 'tested_against'
       AND tested_product.lifecycle_status = 'verified'
      JOIN memory_nodes product
        ON product.id = tested_product.target_node_id
       AND product.node_type = 'technology_product'
      JOIN memory_edges product_version
        ON product_version.source_node_id = product.id
       AND product_version.edge_type = 'has_exact_version'
       AND product_version.lifecycle_status = 'verified'
      JOIN memory_nodes version
        ON version.id = product_version.target_node_id
       AND version.node_type = 'exact_version_fingerprint'
      JOIN memory_edges tested_version
        ON tested_version.source_node_id = procedure.id
       AND tested_version.edge_type = 'tested_against'
       AND tested_version.target_node_id = version.id
       AND tested_version.lifecycle_status = 'verified'
      JOIN memory_edges cve_product
        ON cve_product.source_node_id = cve.id
       AND cve_product.edge_type = 'affects'
       AND cve_product.target_node_id = product.id
       AND cve_product.lifecycle_status = 'verified'
      JOIN memory_edges cve_version
        ON cve_version.source_node_id = cve.id
       AND cve_version.edge_type = 'affects'
       AND cve_version.target_node_id = version.id
       AND cve_version.lifecycle_status = 'verified'
      JOIN attack_knowledge_bundle_edges be_implementation
        ON be_implementation.bundle_id = bundle.id
       AND be_implementation.materialized_edge_id = implementation.id
      JOIN attack_knowledge_bundle_edges be_exploitation
        ON be_exploitation.bundle_id = bundle.id
       AND be_exploitation.materialized_edge_id = exploitation.id
      JOIN attack_knowledge_bundle_edges be_tested_product
        ON be_tested_product.bundle_id = bundle.id
       AND be_tested_product.materialized_edge_id = tested_product.id
      JOIN attack_knowledge_bundle_edges be_product_version
        ON be_product_version.bundle_id = bundle.id
       AND be_product_version.materialized_edge_id = product_version.id
      JOIN attack_knowledge_bundle_edges be_tested_version
        ON be_tested_version.bundle_id = bundle.id
       AND be_tested_version.materialized_edge_id = tested_version.id
      JOIN attack_knowledge_bundle_edges be_cve_product
        ON be_cve_product.bundle_id = bundle.id
       AND be_cve_product.materialized_edge_id = cve_product.id
      JOIN attack_knowledge_bundle_edges be_cve_version
        ON be_cve_version.bundle_id = bundle.id
       AND be_cve_version.materialized_edge_id = cve_version.id
      JOIN memory_sources script_source
        ON script_source.node_id = script.id
       AND script_source.source_type =
         'historical_attack_knowledge_source_candidate'
      JOIN historical_private_source_bindings private_binding
        ON private_binding.memory_source_id = script_source.id
       AND private_binding.source_hash = script_source.source_hash
      JOIN historical_attack_knowledge_source_occurrences occurrence
        ON script_source.source_id =
          occurrence.candidate_id || ':' || occurrence.migration_id
       AND occurrence.source_reference = private_binding.source_reference
       AND occurrence.source_hash = private_binding.source_hash
      JOIN historical_attack_knowledge_bundle_sources bundle_source
        ON bundle_source.bundle_id = bundle.id
       AND bundle_source.candidate_id = occurrence.candidate_id
       AND bundle_source.source_hash = occurrence.source_hash
      JOIN historical_attack_knowledge_verified_bundle_links verified_source
        ON verified_source.bundle_id = bundle_source.bundle_id
       AND verified_source.receipt_id = bundle_source.receipt_id
       AND verified_source.candidate_id = bundle_source.candidate_id
       AND verified_source.source_hash = bundle_source.source_hash
      JOIN reusable_knowledge_outcome_links success
        ON success.memory_node_id = procedure.id
       AND success.outcome_tag = 'success'
      JOIN attack_attempts successful_attempt
        ON successful_attempt.id = success.attack_attempt_id
       AND successful_attempt.status = 'succeeded'
      JOIN attack_attempt_knowledge_contexts successful_context
        ON successful_context.attack_attempt_id = successful_attempt.id
       AND successful_context.procedure_node_id = procedure.id
      JOIN evidence success_proof
        ON success_proof.id = success.evidence_id
       AND success_proof.verification_state = 'verified'
       AND lower(trim(success_proof.evidence_type)) <> 'command_output'
      WHERE bundle.status = 'materialized'
        AND script.scope = 'global' AND script.engagement_id IS NULL
        AND script.mission_id IS NULL AND script.lifecycle_status = 'verified'
        AND script.confirmation_state = 'confirmed'
        AND procedure.scope = 'global' AND procedure.engagement_id IS NULL
        AND procedure.mission_id IS NULL
        AND procedure.lifecycle_status = 'verified'
        AND procedure.confirmation_state = 'confirmed'
        AND product.scope = 'global' AND product.engagement_id IS NULL
        AND product.mission_id IS NULL AND product.lifecycle_status = 'verified'
        AND product.confirmation_state = 'confirmed'
        AND version.scope = 'global' AND version.engagement_id IS NULL
        AND version.mission_id IS NULL AND version.lifecycle_status = 'verified'
        AND version.confirmation_state = 'confirmed'
        AND cve.scope = 'global' AND cve.engagement_id IS NULL
        AND cve.mission_id IS NULL AND cve.lifecycle_status = 'verified'
        AND cve.confirmation_state = 'confirmed'
        AND EXISTS (
          SELECT 1 FROM json_each(successful_context.product_node_ids_json)
          WHERE value = product.id
        )
        AND EXISTS (
          SELECT 1 FROM json_each(successful_context.version_node_ids_json)
          WHERE value = version.id
        )
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events success_custody
          WHERE success_custody.evidence_id = success_proof.id
            AND success_custody.event_type = 'verified'
        )
        AND (
          SELECT COUNT(DISTINCT candidate.proposed_node_id)
          FROM attack_knowledge_bundle_candidates member
          JOIN attack_knowledge_candidate_registry registry
            ON registry.content_fingerprint = member.content_fingerprint
          JOIN memory_candidates candidate
            ON candidate.id = registry.candidate_id
          WHERE member.bundle_id = bundle.id
            AND candidate.proposed_node_id IN (
              script.id, procedure.id, product.id, version.id, cve.id
            )
        ) = 5
      ORDER BY script.id, procedure.id, product.id, version.id, cve.id
      LIMIT ?
    `).all(limit) as Array<{
      readonly bundle_id: string;
      readonly source_candidate_id: string;
      readonly migration_id: string;
      readonly source_reference: string;
      readonly source_hash: string;
      readonly script_node_id: string;
      readonly procedure_node_id: string;
      readonly product_node_id: string;
      readonly version_node_id: string;
      readonly cve_node_id: string;
      readonly language: string;
      readonly script_title: string;
      readonly procedure_title: string;
      readonly product_title: string;
      readonly version_title: string;
      readonly cve_title: string;
      readonly attack_attempt_id: string;
      readonly evidence_id: string;
    }>;
    const entries = rows.map((row): HistoricalExecutableScriptEligibilityEntry => ({
      selection: {
        bundleId: row.bundle_id,
        sourceCandidateId: row.source_candidate_id,
        migrationId: row.migration_id,
        sourceReference: row.source_reference,
        expectedSourceHash: row.source_hash,
        scriptNodeId: row.script_node_id,
        procedureNodeId: row.procedure_node_id,
        productNodeId: row.product_node_id,
        versionNodeId: row.version_node_id,
        cveNodeId: row.cve_node_id,
      },
      language: row.language,
      scriptTitle: row.script_title,
      procedureTitle: row.procedure_title,
      productTitle: row.product_title,
      versionTitle: row.version_title,
      cveTitle: row.cve_title,
      successfulAttemptId: row.attack_attempt_id,
      successEvidenceId: row.evidence_id,
      executableByCurrentRuntime: row.language === "python",
    }));
    const languageCounts = Object.fromEntries(
      languageRows.map(({ language, count }) => [language, Number(count)]),
    );
    const eligibleKeys = new Set(entries.map(({ selection }) =>
      `${selection.scriptNodeId}\u0000${selection.expectedSourceHash}`));
    const custodiedScripts = custodyRows.map(
      (row): HistoricalExecutableScriptCustodyEntry => {
        const executableByCurrentRuntime = row.language === "python";
        const exactBoundVerifiedSuccessEligible = eligibleKeys.has(
          `${row.script_node_id}\u0000${row.source_hash}`,
        );
        return Object.freeze({
          scriptNodeId: row.script_node_id,
          scriptTitle: row.script_title,
          language: row.language,
          sourceHash: row.source_hash,
          executableByCurrentRuntime,
          exactBoundVerifiedSuccessEligible,
          reasonCategories: Object.freeze([
            ...(!executableByCurrentRuntime
              ? ["runtime_binding_unavailable"]
              : []),
            ...(!exactBoundVerifiedSuccessEligible
              ? ["exact_same_bundle_verified_success_binding_missing"]
              : []),
          ]),
        });
      },
    );
    return Object.freeze({
      schemaVersion: "ti-scale.historical-executable-script-eligibility.v1",
      historicalScriptNodeCount: Object.values(languageCounts)
        .reduce((sum, count) => sum + count, 0),
      languageCounts,
      exactBoundVerifiedSuccessCount: entries.length,
      executableByCurrentRuntimeCount: entries.filter(
        ({ executableByCurrentRuntime }) => executableByCurrentRuntime,
      ).length,
      custodiedScripts,
      entries,
      generatedAt: this.#clock().toISOString(),
    });
  }

  preview(raw: HistoricalExecutableScriptPromotionInput): HistoricalExecutableScriptPromotionPreview {
    const input = normalizedInput(raw);
    const selection = input.selection;
    const nodes = this.#exactNodes(selection);
    this.#assertSameBundle(selection, nodes);
    this.#assertExactEdges(selection);
    const sourceRow = this.#sourceCustody(selection);
    const source = this.#readExactSource(sourceRow);
    assertNoEmbeddedSecrets(source);
    const scriptBody = parseBody(nodes.script.body);
    if (scriptBody.contentHash !== selection.expectedSourceHash
      || scriptBody.language !== input.documentation.language) {
      fail(
        "historical_script_memory_hash_mismatch",
        "The reviewed script node does not attest this exact source hash and language.",
      );
    }
    const success = this.#verifiedPriorSuccess(selection);
    const name = canonicalName(sourceRow.source_hash, input.documentation.name);
    const material = {
      schemaVersion: HISTORICAL_EXECUTABLE_SCRIPT_PREVIEW_SCHEMA,
      destinationMissionId: sourceRow.destination_mission_id,
      destinationRunId: sourceRow.destination_run_id,
      canonicalName: name,
      sourceHash: sourceRow.source_hash,
      sourceByteSize: sourceRow.byte_size,
      source,
      sourceReference: selection.sourceReference,
      bundleId: selection.bundleId,
      sourceCandidateId: selection.sourceCandidateId,
      nodeBindings: {
        script: { id: nodes.script.id, title: nodes.script.title },
        procedure: { id: nodes.procedure.id, title: nodes.procedure.title },
        product: { id: nodes.product.id, title: nodes.product.title },
        version: { id: nodes.version.id, title: nodes.version.title },
        cve: { id: nodes.cve.id, title: nodes.cve.title },
      },
      successfulAttemptId: success.attack_attempt_id,
      successEvidenceId: success.evidence_id,
      sourceVerificationEvidenceId: sourceRow.verification_evidence_id,
      documentation: input.documentation,
      executableByCurrentRuntime: true as const,
      runtimeBindingId: REVIEWED_PYTHON_INTERPRETER_BINDING_ID,
      publicProvider: false as const,
      targetContact: false as const,
      sourceExecution: false as const,
    };
    return Object.freeze({
      ...material,
      previewHash: digestCanonicalJson(material, {
        maxBytes: 2 * 1_024 * 1_024,
        maxDepth: 32,
      }).sha256,
    });
  }

  async promote(
    raw: HistoricalExecutableScriptPromotionInput,
    fence: HistoricalExecutableScriptPromotionFence,
  ): Promise<HistoricalExecutableScriptPromotionResult> {
    const input = normalizedInput(raw);
    const preview = this.preview(input);
    this.#assertFence(preview, fence);
    this.#assertVaultProjectionAvailable();
    const replay = this.#findReplay(preview);
    if (replay) {
      const provenance = inImmediateTransaction(
        this.options.database,
        () => this.#bindCanonicalProvenance(
          input,
          preview,
          replay.scriptArtifact,
        ),
      );
      return this.#projectPromotedNode({
        ...replay,
        provenanceSourceId: provenance.sourceId,
        provenanceAuditId: provenance.auditId,
      }, input.selection.scriptNodeId, input.actorId);
    }

    const validationRequest: HistoricalExecutableScriptValidationRequest = Object.freeze({
      schemaVersion: HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_SCHEMA,
      bundleId: preview.bundleId,
      migrationId: input.selection.migrationId,
      sourceCandidateId: preview.sourceCandidateId,
      sourceReference: preview.sourceReference,
      sourceHash: preview.sourceHash,
      source: preview.source,
      language: input.documentation.language,
      publicProvider: false,
      targetContact: false,
      sourceExecution: false,
    });
    const receipt = await this.options.validator.validate(validationRequest);
    this.#assertValidationReceipt(receipt, validationRequest);

    const finalPreview = this.preview(input);
    this.#assertFence(finalPreview, fence);
    if (finalPreview.previewHash !== preview.previewHash) {
      fail("historical_script_preview_changed", "Historical source or reviewed bindings changed during local validation.");
    }

    const persisted = inImmediateTransaction(this.options.database, () => {
      const concurrentReplay = this.#findReplay(finalPreview);
      if (concurrentReplay) return concurrentReplay;
      const validationArtifactId = this.#persistValidationArtifact(finalPreview, receipt);
      const script = this.options.scripts.create({
        missionId: finalPreview.destinationMissionId,
        runId: finalPreview.destinationRunId,
        name: finalPreview.canonicalName,
        language: input.documentation.language,
        source: finalPreview.source,
        laymanExplanation: input.documentation.laymanExplanation,
        technicalPurpose: input.documentation.technicalPurpose,
        inputs: input.documentation.inputs,
        expectedOutputs: input.documentation.expectedOutputs,
        prerequisites: input.documentation.prerequisites,
        dependencies: input.documentation.dependencies,
        touches: input.documentation.touches,
        sideEffects: input.documentation.sideEffects,
        riskClass: input.documentation.riskClass,
        reversibility: input.documentation.reversibility,
        cleanupNotes: input.documentation.cleanupNotes,
        secretsHandling: input.documentation.secretsHandling,
        evidenceExpectations: input.documentation.evidenceExpectations,
        validation: {
          state: "approved",
          summary: "The operator-reviewed byte-identical historical source passed isolated non-executing local validation.",
          tests: receipt.tests,
          testArtifactId: validationArtifactId,
        },
        provenance: {
          origin: "imported",
          explanation: "Explicit operator promotion of exact verified historical custody with same-bundle technology, CVE, procedure, and prior-success evidence.",
          sourceRefs: [
            finalPreview.sourceReference,
            finalPreview.sourceCandidateId,
            finalPreview.bundleId,
            finalPreview.successfulAttemptId,
            finalPreview.successEvidenceId,
            finalPreview.sourceVerificationEvidenceId,
            receipt.receiptId,
          ],
        },
        sensitivity: input.documentation.sensitivity,
      }, { id: input.actorId, type: "operator" });
      const provenance = this.#bindCanonicalProvenance(
        input,
        finalPreview,
        script,
      );
      const occurredAt = this.#clock().toISOString();
      const promotionAuditId = this.#audit.append({
        missionId: script.missionId,
        ...(script.runId ? { runId: script.runId } : {}),
        actor: { id: input.actorId, type: "operator" },
        action: "historical_executable_script.promoted",
        resourceType: "script_artifact",
        resourceId: script.id,
        reason: input.reason,
        details: {
          previewHash: finalPreview.previewHash,
          sourceHash: finalPreview.sourceHash,
          sourceCandidateId: finalPreview.sourceCandidateId,
          sourceReference: finalPreview.sourceReference,
          bundleId: finalPreview.bundleId,
          scriptNodeId: input.selection.scriptNodeId,
          procedureNodeId: input.selection.procedureNodeId,
          productNodeId: input.selection.productNodeId,
          versionNodeId: input.selection.versionNodeId,
          cveNodeId: input.selection.cveNodeId,
          successfulAttemptId: finalPreview.successfulAttemptId,
          successEvidenceId: finalPreview.successEvidenceId,
          sourceVerificationEvidenceId: finalPreview.sourceVerificationEvidenceId,
          validationArtifactId,
          validationReceiptId: receipt.receiptId,
          validationReceiptHash: receipt.receiptHash,
          provenanceSourceId: provenance.sourceId,
          provenanceAuditId: provenance.auditId,
          publicProvider: false,
          targetContactDuringPromotion: false,
          sourceExecutedDuringPromotion: false,
        },
        occurredAt,
      });
      return Object.freeze({
        schemaVersion: HISTORICAL_EXECUTABLE_SCRIPT_PROMOTION_SCHEMA,
        status: "promoted" as const,
        scriptArtifact: script,
        validationArtifactId,
        validationReceiptId: receipt.receiptId,
        validationReceiptHash: receipt.receiptHash,
        promotionAuditId,
        previewHash: finalPreview.previewHash,
        publicProvider: false as const,
        targetContactDuringPromotion: false as const,
        sourceExecutedDuringPromotion: false as const,
      });
    });
    const provenance = this.#requireCanonicalProvenance(
      input,
      finalPreview,
      persisted.scriptArtifact,
    );
    return this.#projectPromotedNode({
      ...persisted,
      provenanceSourceId: provenance.sourceId,
      provenanceAuditId: provenance.auditId,
    }, input.selection.scriptNodeId, input.actorId);
  }

  #exactNodes(selection: HistoricalExecutableScriptSelection): Readonly<{
    script: NodeRow;
    procedure: NodeRow;
    product: NodeRow;
    version: NodeRow;
    cve: NodeRow;
  }> {
    const bindings = [
      ["script", selection.scriptNodeId, "script_artifact"],
      ["procedure", selection.procedureNodeId, "attack_procedure"],
      ["product", selection.productNodeId, "technology_product"],
      ["version", selection.versionNodeId, "exact_version_fingerprint"],
      ["cve", selection.cveNodeId, "cve"],
    ] as const;
    const result = new Map<string, NodeRow>();
    for (const [role, id, expectedType] of bindings) {
      const row = this.options.database.prepare(`
        SELECT id, node_type, title, body FROM memory_nodes
        WHERE id = ? AND node_type = ? AND scope = 'global'
          AND engagement_id IS NULL AND mission_id IS NULL
          AND lifecycle_status = 'verified'
          AND confirmation_state = 'confirmed'
          AND (expires_at IS NULL OR expires_at > ?)
      `).get(id, expectedType, this.#clock().toISOString()) as NodeRow | undefined;
      if (!row) fail("historical_script_node_ineligible", `The selected ${role} node is not active verified global knowledge.`);
      result.set(role, row);
    }
    return {
      script: result.get("script")!,
      procedure: result.get("procedure")!,
      product: result.get("product")!,
      version: result.get("version")!,
      cve: result.get("cve")!,
    };
  }

  #assertSameBundle(
    selection: HistoricalExecutableScriptSelection,
    nodes: Readonly<Record<"script" | "procedure" | "product" | "version" | "cve", NodeRow>>,
  ): void {
    const nodeIds = Object.values(nodes).map(({ id }) => id);
    const row = this.options.database.prepare(`
      SELECT bundle.status,
        COUNT(DISTINCT candidate.proposed_node_id) AS matched_nodes
      FROM attack_knowledge_bundles bundle
      JOIN attack_knowledge_bundle_candidates member
        ON member.bundle_id = bundle.id
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = member.content_fingerprint
      JOIN memory_candidates candidate
        ON candidate.id = registry.candidate_id
      WHERE bundle.id = ?
        AND candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND candidate.proposed_node_id IN (${nodeIds.map(() => "?").join(",")})
      GROUP BY bundle.id
    `).get(selection.bundleId, ...nodeIds) as {
      readonly status: string;
      readonly matched_nodes: number;
    } | undefined;
    if (!row || row.status !== "materialized" || Number(row.matched_nodes) !== nodeIds.length) {
      fail("historical_script_bundle_binding_invalid", "All five reviewed nodes must originate from the same materialized historical bundle.");
    }
  }

  #assertExactEdges(selection: HistoricalExecutableScriptSelection): void {
    const ids = {
      script: selection.scriptNodeId,
      procedure: selection.procedureNodeId,
      product: selection.productNodeId,
      version: selection.versionNodeId,
      cve: selection.cveNodeId,
    } as const;
    for (const [sourceRole, edgeType, targetRole] of REQUIRED_EDGE_BINDINGS) {
      const row = this.options.database.prepare(`
        SELECT edge.id FROM memory_edges edge
        JOIN attack_knowledge_bundle_edges bundle_edge
          ON bundle_edge.bundle_id = ?
         AND bundle_edge.materialized_edge_id = edge.id
         AND bundle_edge.edge_type = edge.edge_type
        WHERE edge.source_node_id = ? AND edge.edge_type = ?
          AND edge.target_node_id = ?
          AND edge.scope = 'global'
          AND edge.engagement_id IS NULL AND edge.mission_id IS NULL
          AND edge.lifecycle_status = 'verified'
          AND (edge.expires_at IS NULL OR edge.expires_at > ?)
        ORDER BY edge.version DESC LIMIT 1
      `).get(
        selection.bundleId,
        ids[sourceRole],
        edgeType,
        ids[targetRole],
        this.#clock().toISOString(),
      );
      if (!row) {
        fail("historical_script_graph_binding_missing", `Required verified graph binding is missing: ${sourceRole} ${edgeType} ${targetRole}.`);
      }
    }
  }

  #sourceCustody(selection: HistoricalExecutableScriptSelection): SourceRow {
    const row = this.options.database.prepare(`
      SELECT source_object.source_path, source_object.source_sha256 AS source_hash,
        source_object.byte_size, source_object.source_device,
        source_object.source_inode,
        verified.evidence_id AS verification_evidence_id,
        context.mission_id AS destination_mission_id,
        context.run_id AS destination_run_id
      FROM historical_attack_knowledge_bundle_sources bundle_source
      JOIN historical_attack_knowledge_verified_bundle_links verified
        ON verified.bundle_id = bundle_source.bundle_id
       AND verified.receipt_id = bundle_source.receipt_id
       AND verified.candidate_id = bundle_source.candidate_id
       AND verified.source_hash = bundle_source.source_hash
      JOIN historical_attack_knowledge_source_occurrences occurrence
        ON occurrence.candidate_id = bundle_source.candidate_id
       AND occurrence.migration_id = ?
       AND occurrence.source_reference = ?
       AND occurrence.source_hash = bundle_source.source_hash
      JOIN legacy_migration_source_objects source_object
        ON source_object.migration_id = occurrence.migration_id
       AND source_object.source_reference = occurrence.source_reference
       AND source_object.source_sha256 = occurrence.source_hash
       AND source_object.verification_status = 'verified_reference'
       AND source_object.object_kind IN ('accepted', 'source')
      JOIN historical_attack_knowledge_import_contexts context
        ON context.migration_id = occurrence.migration_id
      JOIN memory_sources memory_source
        ON memory_source.node_id = ?
       AND memory_source.source_type =
         'historical_attack_knowledge_source_candidate'
       AND memory_source.source_id =
         occurrence.candidate_id || ':' || occurrence.migration_id
       AND memory_source.source_hash = occurrence.source_hash
      JOIN historical_private_source_bindings private_binding
        ON private_binding.memory_source_id = memory_source.id
       AND private_binding.source_candidate_id = occurrence.candidate_id
       AND private_binding.migration_id = occurrence.migration_id
       AND private_binding.source_reference = occurrence.source_reference
       AND private_binding.source_hash = occurrence.source_hash
      JOIN artifacts private_artifact
        ON private_artifact.id = private_binding.artifact_id
       AND private_artifact.content_hash = occurrence.source_hash
       AND private_artifact.sensitivity IN ('private', 'restricted')
      JOIN evidence proof
        ON proof.id = verified.evidence_id
       AND proof.content_hash = occurrence.source_hash
       AND proof.verification_state = 'verified'
       AND lower(trim(proof.evidence_type)) <> 'command_output'
      WHERE bundle_source.bundle_id = ?
        AND bundle_source.candidate_id = ?
        AND bundle_source.source_hash = ?
        AND NOT EXISTS (
          SELECT 1 FROM legacy_migration_quarantine quarantine
          WHERE (
            quarantine.source_content_sha256 = occurrence.source_hash
            OR quarantine.source_sha256 = occurrence.source_hash
          )
          AND lower(quarantine.category || ' ' || quarantine.reason)
            GLOB '*secret*'
        )
      ORDER BY verified.verified_at DESC
      LIMIT 1
    `).get(
      selection.migrationId,
      selection.sourceReference,
      selection.scriptNodeId,
      selection.bundleId,
      selection.sourceCandidateId,
      selection.expectedSourceHash,
    ) as SourceRow | undefined;
    if (!row || row.source_hash !== selection.expectedSourceHash) {
      fail("historical_script_source_custody_ineligible", "Exact operator-verified historical source custody is unavailable for this same-bundle script.");
    }
    return row;
  }

  #readExactSource(row: SourceRow): string {
    if (!isAbsolute(row.source_path) || normalize(row.source_path) !== row.source_path) {
      fail("historical_script_source_path_invalid", "Verified historical source path is not canonical.");
    }
    let descriptor: number | undefined;
    try {
      descriptor = openSync(row.source_path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = fstatSync(descriptor);
      if (!stat.isFile()
        || Number(stat.dev) !== Number(row.source_device)
        || Number(stat.ino) !== Number(row.source_inode)
        || stat.size !== Number(row.byte_size)
        || stat.size < 1
        || stat.size > MAX_SOURCE_BYTES) {
        fail("historical_script_source_identity_changed", "Historical source no longer matches its immutable device, inode, size, and regular-file custody.");
      }
      const bytes = readFileSync(descriptor);
      const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      if (source.includes("\0") || sha256(source) !== row.source_hash) {
        fail("historical_script_source_bytes_changed", "Historical source bytes no longer match the reviewed SHA-256 custody.");
      }
      return source;
    } catch (error) {
      if (error instanceof HistoricalExecutableScriptPromotionError) throw error;
      fail("historical_script_source_read_failed", "Historical source could not be read through the no-follow local custody boundary.");
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
    return fail(
      "historical_script_source_read_failed",
      "Historical source could not be read through the no-follow local custody boundary.",
    );
  }

  #verifiedPriorSuccess(selection: HistoricalExecutableScriptSelection): SuccessRow {
    const row = this.options.database.prepare(`
      SELECT outcome.attack_attempt_id, outcome.evidence_id
      FROM reusable_knowledge_outcome_links outcome
      JOIN attack_attempts attempt
        ON attempt.id = outcome.attack_attempt_id
       AND attempt.status = 'succeeded'
      JOIN attack_attempt_knowledge_contexts context
        ON context.attack_attempt_id = attempt.id
       AND context.procedure_node_id = ?
      JOIN evidence proof
        ON proof.id = outcome.evidence_id
       AND proof.mission_id = attempt.mission_id
       AND proof.run_id = attempt.run_id
       AND proof.verification_state = 'verified'
       AND lower(trim(proof.evidence_type)) <> 'command_output'
      WHERE outcome.memory_node_id = ?
        AND outcome.outcome_tag = 'success'
        AND EXISTS (
          SELECT 1 FROM json_each(context.product_node_ids_json)
          WHERE value = ?
        )
        AND EXISTS (
          SELECT 1 FROM json_each(context.version_node_ids_json)
          WHERE value = ?
        )
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = proof.id
            AND custody.event_type = 'verified'
        )
      ORDER BY outcome.created_at DESC
      LIMIT 1
    `).get(
      selection.procedureNodeId,
      selection.procedureNodeId,
      selection.productNodeId,
      selection.versionNodeId,
    ) as SuccessRow | undefined;
    if (!row) {
      fail("historical_script_verified_success_required", "The exact procedure/product/version binding has no canonical prior successful attempt with verified evidence.");
    }
    return row;
  }

  #assertFence(
    preview: HistoricalExecutableScriptPromotionPreview,
    fence: HistoricalExecutableScriptPromotionFence,
  ): void {
    if (!fence.reviewedExactSourceAndBindings
      || !fence.acknowledgedNoAutomaticExecution
      || fence.expectedPreviewHash !== preview.previewHash
      || fence.expectedSourceHash !== preview.sourceHash) {
      fail("historical_script_operator_fence_invalid", "Promotion requires an exact fresh operator-reviewed preview and source-hash acknowledgement.");
    }
  }

  #assertValidationReceipt(
    receipt: HistoricalExecutableScriptValidationReceipt,
    request: HistoricalExecutableScriptValidationRequest,
  ): void {
    const expectedHash = digestCanonicalJson(receiptMaterial(receipt), {
      maxBytes: 1_048_576,
      maxDepth: 24,
    }).sha256;
    if (receipt.schemaVersion !== HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_RECEIPT_SCHEMA
      || receipt.bundleId !== request.bundleId
      || receipt.migrationId !== request.migrationId
      || receipt.sourceCandidateId !== request.sourceCandidateId
      || receipt.sourceHash !== request.sourceHash
      || receipt.language !== request.language
      || receipt.publicProvider
      || receipt.targetContact
      || receipt.sourceExecution
      || !receipt.isolatedLocalValidation
      || receipt.tests.length < 2
      || receipt.tests.some(({ status }) => status !== "passed")
      || !SHA256.test(receipt.receiptHash)
      || receipt.receiptHash !== expectedHash) {
      fail("historical_script_validation_receipt_invalid", "Local validation did not attest the exact unchanged source under the non-executing private boundary.");
    }
  }

  #persistValidationArtifact(
    preview: HistoricalExecutableScriptPromotionPreview,
    receipt: HistoricalExecutableScriptValidationReceipt,
  ): string {
    const id = stableId("artifact_historical_script_validation", [
      preview.destinationMissionId,
      preview.destinationRunId,
      preview.previewHash,
      receipt.receiptHash,
    ]);
    const existing = this.options.database.prepare(`
      SELECT mission_id, run_id, artifact_type, content_hash, metadata_json
      FROM artifacts WHERE id = ?
    `).get(id) as {
      readonly mission_id: string;
      readonly run_id: string | null;
      readonly artifact_type: string;
      readonly content_hash: string;
      readonly metadata_json: string;
    } | undefined;
    const metadata = digestCanonicalJson(receipt, {
      maxBytes: 1_048_576,
      maxDepth: 24,
    }).canonicalJson;
    if (existing) {
      if (existing.mission_id !== preview.destinationMissionId
        || existing.run_id !== preview.destinationRunId
        || existing.artifact_type !== "script_test_result"
        || existing.content_hash !== receipt.receiptHash
        || existing.metadata_json !== metadata) {
        fail("historical_script_validation_artifact_conflict", "A different immutable validation receipt occupies this deterministic identity.");
      }
      return id;
    }
    this.options.database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json,
        created_at
      ) VALUES (?, ?, ?, 'guided', 'script_test_result', ?, ?, ?,
        'application/json', 'private', ?, ?)
    `).run(
      id,
      preview.destinationMissionId,
      preview.destinationRunId,
      `ti-scale://historical-script-validation/${receipt.receiptId}`,
      receipt.receiptHash,
      Buffer.byteLength(metadata, "utf8"),
      metadata,
      this.#clock().toISOString(),
    );
    return id;
  }

  #assertVaultProjectionAvailable(): void {
    if (!this.options.vaultProjector) {
      fail(
        "historical_script_vault_projector_required",
        "Executable historical promotion requires the connected-Vault projector so the exact verified memory node remains discoverable.",
      );
    }
    const connected = this.options.database.prepare(`
      SELECT COUNT(*) AS count FROM vault_connections WHERE status = 'connected'
    `).get() as { readonly count: number };
    if (Number(connected.count) < 1) {
      fail(
        "historical_script_connected_vault_required",
        "Executable historical promotion requires at least one active connected Obsidian Vault.",
      );
    }
  }

  #bindCanonicalProvenance(
    input: HistoricalExecutableScriptPromotionInput,
    preview: HistoricalExecutableScriptPromotionPreview,
    script: ScriptArtifactDetail,
  ): ProvenanceBinding {
    const sourceId = stableId("msrc", [
      input.selection.scriptNodeId,
      "script_artifact",
      script.id,
    ]);
    const occurredAt = this.#clock().toISOString();
    this.options.database.prepare(`
      INSERT INTO memory_sources (
        id, node_id, source_type, source_id, mission_id, run_id,
        evidence_id, source_hash, acquired_at, created_at
      ) VALUES (?, ?, 'script_artifact', ?, ?, ?, NULL, ?, ?, ?)
      ON CONFLICT(node_id, source_type, source_id) DO NOTHING
    `).run(
      sourceId,
      input.selection.scriptNodeId,
      script.id,
      script.missionId,
      script.runId,
      script.contentHash,
      occurredAt,
      occurredAt,
    );
    const stored = this.options.database.prepare(`
      SELECT id, mission_id, run_id, evidence_id, source_hash
      FROM memory_sources
      WHERE node_id = ? AND source_type = 'script_artifact' AND source_id = ?
    `).get(input.selection.scriptNodeId, script.id) as {
      readonly id: string;
      readonly mission_id: string | null;
      readonly run_id: string | null;
      readonly evidence_id: string | null;
      readonly source_hash: string | null;
    } | undefined;
    if (!stored
      || stored.id !== sourceId
      || stored.mission_id !== script.missionId
      || stored.run_id !== script.runId
      || stored.evidence_id !== null
      || stored.source_hash !== script.contentHash
      || script.contentHash !== preview.sourceHash) {
      fail(
        "historical_script_canonical_provenance_conflict",
        "The verified historical script node has a conflicting canonical ScriptArtifact provenance binding.",
      );
    }
    const expectedDetails = {
      memorySourceId: sourceId,
      scriptNodeId: input.selection.scriptNodeId,
      scriptArtifactId: script.id,
      sourceHash: script.contentHash,
      previewHash: preview.previewHash,
      bundleId: preview.bundleId,
      sourceCandidateId: preview.sourceCandidateId,
      validationArtifactId: script.validation.testArtifactId ?? null,
      immutable: true,
    };
    const existingAudit = this.options.database.prepare(`
      SELECT id, details_json FROM audit_records
      WHERE mission_id = ? AND run_id = ?
        AND action = 'historical_executable_script.provenance_bound'
        AND resource_type = 'memory_source' AND resource_id = ?
      ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get(script.missionId, script.runId, sourceId) as {
      readonly id: string;
      readonly details_json: string;
    } | undefined;
    if (existingAudit) {
      const details = parseBody(existingAudit.details_json);
      if (Object.entries(expectedDetails).some(
        ([key, value]) => details[key] !== value,
      )) {
        fail(
          "historical_script_provenance_audit_conflict",
          "The immutable ScriptArtifact provenance audit does not match the exact verified memory binding.",
        );
      }
      return Object.freeze({ sourceId, auditId: existingAudit.id });
    }
    const auditId = this.#audit.append({
      missionId: script.missionId,
      ...(script.runId ? { runId: script.runId } : {}),
      actor: { id: input.actorId, type: "operator" },
      action: "historical_executable_script.provenance_bound",
      resourceType: "memory_source",
      resourceId: sourceId,
      reason: input.reason,
      details: expectedDetails,
      occurredAt,
    });
    return Object.freeze({ sourceId, auditId });
  }

  #requireCanonicalProvenance(
    input: HistoricalExecutableScriptPromotionInput,
    preview: HistoricalExecutableScriptPromotionPreview,
    script: ScriptArtifactDetail,
  ): ProvenanceBinding {
    const sourceId = stableId("msrc", [
      input.selection.scriptNodeId,
      "script_artifact",
      script.id,
    ]);
    const source = this.options.database.prepare(`
      SELECT id, mission_id, run_id, evidence_id, source_hash
      FROM memory_sources
      WHERE id = ? AND node_id = ? AND source_type = 'script_artifact'
        AND source_id = ?
    `).get(sourceId, input.selection.scriptNodeId, script.id) as {
      readonly id: string;
      readonly mission_id: string | null;
      readonly run_id: string | null;
      readonly evidence_id: string | null;
      readonly source_hash: string | null;
    } | undefined;
    if (!source
      || source.mission_id !== script.missionId
      || source.run_id !== script.runId
      || source.evidence_id !== null
      || source.source_hash !== preview.sourceHash) {
      fail(
        "historical_script_canonical_provenance_missing",
        "The promoted ScriptArtifact is not immutably linked to its verified global memory node.",
      );
    }
    const audit = this.options.database.prepare(`
      SELECT id, details_json FROM audit_records
      WHERE mission_id = ? AND run_id = ?
        AND action = 'historical_executable_script.provenance_bound'
        AND resource_type = 'memory_source' AND resource_id = ?
      ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get(script.missionId, script.runId, sourceId) as {
      readonly id: string;
      readonly details_json: string;
    } | undefined;
    if (!audit) {
      fail(
        "historical_script_provenance_audit_missing",
        "The promoted ScriptArtifact provenance link has no immutable operator audit.",
      );
    }
    const details = parseBody(audit.details_json);
    if (details.memorySourceId !== sourceId
      || details.scriptNodeId !== input.selection.scriptNodeId
      || details.scriptArtifactId !== script.id
      || details.sourceHash !== preview.sourceHash
      || details.previewHash !== preview.previewHash
      || details.immutable !== true) {
      fail(
        "historical_script_provenance_audit_mismatch",
        "The promoted ScriptArtifact provenance audit does not match the exact reviewed memory binding.",
      );
    }
    return Object.freeze({ sourceId, auditId: audit.id });
  }

  #projectPromotedNode(
    persisted: ProvenanceBoundPromotionResult,
    scriptNodeId: string,
    actorId: string,
  ): HistoricalExecutableScriptPromotionResult {
    const report = this.options.vaultProjector!.project([scriptNodeId]);
    const complete = report.attempted > 0
      && report.synchronized === report.attempted
      && report.attentionRequired === 0
      && report.skippedByPolicy === 0
      && report.failures === 0;
    const auditId = this.#audit.append({
      missionId: persisted.scriptArtifact.missionId,
      ...(persisted.scriptArtifact.runId
        ? { runId: persisted.scriptArtifact.runId }
        : {}),
      actor: { id: actorId, type: "operator" },
      action: complete
        ? "historical_executable_script.vault_projection_completed"
        : "historical_executable_script.vault_projection_attention_required",
      resourceType: "memory_node",
      resourceId: scriptNodeId,
      reason: complete
        ? "The promoted canonical ScriptArtifact provenance was projected into every active eligible Obsidian Vault."
        : "The canonical ScriptArtifact remains durable, but one or more active Obsidian Vault projections require attention.",
      details: {
        scriptArtifactId: persisted.scriptArtifact.id,
        provenanceSourceId: persisted.provenanceSourceId,
        requestedNodeIds: report.requestedNodeIds,
        skippedByPolicyNodeIds: report.skippedByPolicyNodeIds,
        attempted: report.attempted,
        synchronized: report.synchronized,
        attentionRequired: report.attentionRequired,
        skippedByPolicy: report.skippedByPolicy,
        failures: report.failures,
        complete,
      },
      occurredAt: this.#clock().toISOString(),
    });
    return Object.freeze({
      ...persisted,
      vaultProjection: Object.freeze({
        ...report,
        complete,
        auditId,
      }),
    });
  }

  #findReplay(
    preview: HistoricalExecutableScriptPromotionPreview,
  ): PersistedPromotionResult | undefined {
    const existing = this.options.scripts.repository.latest(
      preview.destinationMissionId,
      preview.canonicalName,
    );
    if (!existing) return undefined;
    const script = this.options.scripts.get(existing.id);
    if (script.runId !== preview.destinationRunId
      || script.contentHash !== preview.sourceHash
      || script.source !== preview.source
      || script.validation.state !== "approved"
      || !script.validation.testArtifactId) {
      fail("historical_script_promotion_conflict", "A different canonical ScriptArtifact already occupies this historical source identity.");
    }
    const audit = this.options.database.prepare(`
      SELECT id, details_json FROM audit_records
      WHERE mission_id = ? AND run_id = ?
        AND action = 'historical_executable_script.promoted'
        AND resource_type = 'script_artifact' AND resource_id = ?
      ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get(script.missionId, script.runId, script.id) as {
      readonly id: string;
      readonly details_json: string;
    } | undefined;
    if (!audit) {
      fail("historical_script_promotion_audit_missing", "Existing historical ScriptArtifact has no immutable operator-promotion audit.");
    }
    const details = parseBody(audit.details_json);
    if (details.previewHash !== preview.previewHash
      || details.sourceHash !== preview.sourceHash
      || details.validationArtifactId !== script.validation.testArtifactId
      || typeof details.validationReceiptId !== "string"
      || typeof details.validationReceiptHash !== "string"
      || !SHA256.test(details.validationReceiptHash)) {
      fail("historical_script_promotion_audit_mismatch", "Existing historical ScriptArtifact audit does not match this exact reviewed preview.");
    }
    return Object.freeze({
      schemaVersion: HISTORICAL_EXECUTABLE_SCRIPT_PROMOTION_SCHEMA,
      status: "replayed",
      scriptArtifact: script,
      validationArtifactId: script.validation.testArtifactId,
      validationReceiptId: details.validationReceiptId,
      validationReceiptHash: details.validationReceiptHash,
      promotionAuditId: audit.id,
      previewHash: preview.previewHash,
      publicProvider: false,
      targetContactDuringPromotion: false,
      sourceExecutedDuringPromotion: false,
    });
  }
}
