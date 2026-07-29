import { createHash } from "node:crypto";
import type { ExecutionResult } from "../command-runtime";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { OperationalTruthService } from "../intelligence-v24";
import type { LocalProcessToolResult, LocalToolCapabilityManifest } from "../local-tools";
import { digestCanonicalJson } from "../mcp";
import { ActionRepository, type DurableAction } from "../orchestration";
import {
  AUTONOMOUS_CRITERION_OUTCOME_PROVENANCE_SCHEMA_VERSION,
  AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
  autonomousSuccessCriterionId,
} from "./LocalVerifiedEvidenceOutcomeEvaluator";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_WHATWEB_EVIDENCE_TYPE,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION,
  type AutonomousWebSurfacePlanningConfiguration,
} from "./AutonomousWebSurfaceBaseline";
import {
  AUTONOMOUS_WEB_SURFACE_RESULT_SCHEMA_VERSION,
  autonomousWebChildActionEnvelope,
  autonomousWebChildInvocationId,
  type AutonomousWebSurfaceResult,
} from "./AutonomousWebSurfaceExecution";
import {
  authorizeAutonomousDerivedWebOrigins,
  type AuthorizedDerivedWebOrigins,
} from "./AutonomousWebOriginAuthorization";
import { AutonomousReconTopologyProjector } from "./AutonomousReconTopologyProjector";

export const AUTONOMOUS_WEB_EVIDENCE_VERIFIER_SCHEMA_VERSION =
  AUTONOMOUS_WEB_EVIDENCE_PROVENANCE_SCHEMA_VERSION;
export const AUTONOMOUS_WEB_RESULT_DELIVERY_SCHEMA_VERSION =
  "ti-scale.autonomous-web-result-delivery.v1" as const;

const RECEIPT_PREFIX = "idempotency.autonomous-web-evidence.";
const SHA256 = /^[a-f0-9]{64}$/u;
const TRANSIENT_CURL_EXIT_CODES = new Set([5, 6, 7, 18, 35, 52, 55, 56]);

export function autonomousHttpMetadataFailureCode(exitCode: number | null): string {
  if (exitCode === 28) return "autonomous_http_metadata_timeout";
  if (exitCode !== null && TRANSIENT_CURL_EXIT_CODES.has(exitCode)) {
    return "autonomous_http_metadata_transient_network";
  }
  return "autonomous_http_metadata_failed";
}

export class AutonomousWebEvidenceVerificationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "AutonomousWebEvidenceVerificationError";
  }
}

export interface AutonomousWebEvidencePromotionResult {
  readonly executionResult: ExecutionResult;
  readonly logRecordId: string | null;
  readonly observationId: string | null;
  /** New verified web evidence for achieved phases; source evidence for N/A. */
  readonly evidenceIds: readonly string[];
  readonly duplicate: boolean;
}

interface PromotionReceipt {
  readonly schemaVersion: typeof AUTONOMOUS_WEB_EVIDENCE_VERIFIER_SCHEMA_VERSION;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly resultSha256: string;
  readonly logRecordId: string | null;
  readonly observationId: string | null;
  readonly evidenceIds: readonly string[];
  readonly executionResult: ExecutionResult;
}

function plain(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function outputIntegrity(result: LocalProcessToolResult, expectedSha256: string): void {
  const outputSha256 = createHash("sha256")
    .update(result.stdout, "utf8").update("\u0000", "utf8").update(result.stderr, "utf8")
    .digest("hex");
  if (result.outputTruncated || result.termination !== "exited"
    || outputSha256 !== result.outputSha256
    || result.executable.sourceSha256 !== expectedSha256
    || result.executable.snapshotSha256 !== expectedSha256
    || result.sandbox.shell !== false) {
    throw new AutonomousWebEvidenceVerificationError(
      "autonomous_web_child_integrity_invalid",
      "A web child result is truncated, incomplete, or differs from the reviewed executable and output receipt.",
    );
  }
}

function bounded(value: string | undefined, maximum = 240): string | null {
  if (!value) return null;
  return value.replace(/[\u0000-\u001F\u007F]/gu, " ").trim().replace(/\s+/gu, " ").slice(0, maximum) || null;
}

function parseHttp(result: LocalProcessToolResult): Readonly<Record<string, unknown>> {
  if (result.exitCode !== 0 && result.exitCode !== 22) {
    const code = autonomousHttpMetadataFailureCode(result.exitCode);
    throw new AutonomousWebEvidenceVerificationError(
      code,
      code === "autonomous_http_metadata_timeout"
        ? "The bounded HTTP metadata request timed out before an attributable response was available."
        : code === "autonomous_http_metadata_transient_network"
          ? "The bounded HTTP metadata request encountered a transient transport failure before an attributable response was available."
          : "The bounded HTTP metadata request did not return a parseable HTTP response.",
    );
  }
  const lines = result.stdout.split(/\r?\n/u);
  const statuses = lines.flatMap((line) => {
    const match = line.match(/^HTTP\/[0-9.]+\s+([0-9]{3})(?:\s+(.*))?$/u);
    return match ? [{ code: Number(match[1]), reason: bounded(match[2]) }] : [];
  });
  const status = statuses.at(-1);
  if (!status || status.code < 100 || status.code > 599) {
    throw new AutonomousWebEvidenceVerificationError(
      "autonomous_http_status_missing",
      "The bounded HTTP metadata request completed without an attributable HTTP status line.",
    );
  }
  const headers = new Map<string, string>();
  for (const line of lines) {
    const match = line.match(/^([A-Za-z0-9-]{1,80}):\s*(.*)$/u);
    if (match) headers.set(match[1]!.toLowerCase(), match[2] ?? "");
  }
  return Object.freeze({
    statusCode: status.code,
    statusReason: status.reason,
    headerNames: Object.freeze([...headers.keys()].sort()),
    server: bounded(headers.get("server")),
    contentType: bounded(headers.get("content-type")),
    contentLength: /^\d{1,20}$/u.test(headers.get("content-length") ?? "")
      ? headers.get("content-length") : null,
    allow: bounded(headers.get("allow")),
    responseOutputSha256: result.outputSha256,
  });
}

function redactedRawOutput(value: string): string {
  return value
    .replace(/^(set-cookie|set-cookie2|authorization|proxy-authorization):[^\r\n]*$/gimu, "$1: [REDACTED]")
    .replace(/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+/giu, "$1 [REDACTED]")
    .replace(/\b(api[-_]?key|password|secret|session[-_]?token)\s*[:=]\s*[^\s,;]+/giu, "$1=[REDACTED]");
}

function parseWhatWeb(result: LocalProcessToolResult): Readonly<Record<string, unknown>> {
  if (result.exitCode !== 0) {
    throw new AutonomousWebEvidenceVerificationError(
      "autonomous_whatweb_failed",
      "The bounded technology fingerprint process did not complete successfully.",
    );
  }
  const output = result.stdout;
  const values = (name: string): readonly string[] => Object.freeze([
    ...output.matchAll(new RegExp(`${name}\\[([^\\]]{0,500})\\]`, "giu")),
  ].flatMap((match) => bounded(match[1], 300) ?? []).filter(Boolean));
  return Object.freeze({
    httpServerSignals: values("HTTPServer"),
    titleSignals: values("Title"),
    poweredBySignals: values("X-Powered-By"),
    html5Observed: /(?:^|[,\s])HTML5(?:[,\s]|$)/iu.test(output),
    statusSignals: values("Status").filter((value) => /^[0-9]{3}$/u.test(value)),
    identificationStrength: output.trim() ? "bounded_banner_and_markup_signals" : "no_positive_signal",
    responseOutputSha256: result.outputSha256,
  });
}

function parseFfuf(
  result: LocalProcessToolResult,
  origin: string,
  fixedPaths: readonly string[],
): Readonly<Record<string, unknown>> {
  if (result.exitCode !== 0) {
    throw new AutonomousWebEvidenceVerificationError(
      "autonomous_endpoint_discovery_failed",
      "The bounded endpoint-discovery process did not complete successfully.",
    );
  }
  if (fixedPaths.length !== 14 || new Set(fixedPaths).size !== fixedPaths.length) {
    throw new AutonomousWebEvidenceVerificationError(
      "autonomous_endpoint_dictionary_invalid",
      "The reviewed endpoint dictionary no longer contains exactly fourteen unique paths.",
    );
  }
  const expected = new Map(fixedPaths.map((path) => [new URL(path, origin).href, path]));
  const matches: Array<Readonly<Record<string, unknown>>> = [];
  const observedUrls = new Set<string>();
  for (const line of result.stdout.split(/\r?\n/u).filter((value) => value.trim())) {
    let parsed: unknown;
    try { parsed = JSON.parse(line) as unknown; } catch {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_endpoint_output_invalid",
        "The bounded FFUF output contains a non-JSON record.",
      );
    }
    if (!plain(parsed) || typeof parsed.url !== "string"
      || !Number.isSafeInteger(parsed.status)) {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_endpoint_record_invalid",
        "A bounded FFUF result record is missing its canonical URL or HTTP status.",
      );
    }
    let url: URL;
    try { url = new URL(parsed.url); } catch {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_endpoint_url_invalid",
        "A bounded FFUF result contains an invalid URL.",
      );
    }
    const canonicalUrl = url.href;
    const path = expected.get(canonicalUrl);
    const status = Number(parsed.status);
    const permittedStatus = (status >= 200 && status <= 399)
      || status === 401 || status === 403 || status === 405;
    if (!path || url.origin !== new URL(origin).origin || url.username || url.password
      || url.search || url.hash || !permittedStatus || observedUrls.has(canonicalUrl)) {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_endpoint_scope_or_status_invalid",
        "A bounded FFUF result escaped the fixed origin/path/status set or repeated a result.",
      );
    }
    const boundedInteger = (value: unknown): number | null =>
      Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null;
    observedUrls.add(canonicalUrl);
    matches.push(Object.freeze({
      path,
      url: canonicalUrl,
      status,
      length: boundedInteger(parsed.length),
      words: boundedInteger(parsed.words),
      lines: boundedInteger(parsed.lines),
      redirectLocation: bounded(
        typeof parsed.redirectlocation === "string" ? parsed.redirectlocation : undefined,
        1_000,
      ),
    }));
  }
  if (matches.length > fixedPaths.length) {
    throw new AutonomousWebEvidenceVerificationError(
      "autonomous_endpoint_result_bound_exceeded",
      "The bounded FFUF result exceeds the reviewed fourteen-path result bound.",
    );
  }
  return Object.freeze({
    dictionaryVersion: "ti-scale.web-paths.v1",
    checkedPaths: Object.freeze([...fixedPaths]),
    requestBudget: fixedPaths.length,
    maximumConcurrency: 2,
    maximumRatePerSecond: 10,
    recursive: false,
    redirectFollowed: false,
    matchCount: matches.length,
    matches: Object.freeze(matches),
    responseOutputSha256: result.outputSha256,
  });
}

function receipt(value: string): PromotionReceipt {
  const parsed = JSON.parse(value) as unknown;
  if (!plain(parsed) || parsed.schemaVersion !== AUTONOMOUS_WEB_EVIDENCE_VERIFIER_SCHEMA_VERSION
    || typeof parsed.actionId !== "string" || typeof parsed.actionFingerprint !== "string"
    || typeof parsed.resultSha256 !== "string"
    || (parsed.logRecordId !== null && typeof parsed.logRecordId !== "string")
    || (parsed.observationId !== null && typeof parsed.observationId !== "string")
    || !Array.isArray(parsed.evidenceIds)
    || parsed.evidenceIds.some((id) => typeof id !== "string")
    || !plain(parsed.executionResult)) throw new Error("Stored Autonomous web evidence receipt is invalid");
  return parsed as unknown as PromotionReceipt;
}

function duplicateReceipt(
  value: string,
  result: AutonomousWebSurfaceResult,
): AutonomousWebEvidencePromotionResult {
  const stored = receipt(value);
  if (stored.actionId !== result.actionId
    || stored.actionFingerprint !== result.actionFingerprint
    || stored.resultSha256 !== result.resultSha256
    || stored.executionResult.actionId !== result.actionId
    || stored.executionResult.runId !== result.runId
    || stored.executionResult.actionFingerprint !== result.actionFingerprint) {
    throw new AutonomousWebEvidenceVerificationError(
      "autonomous_web_duplicate_result_conflict",
      "A stored idempotency receipt exists for this action, but the incoming fingerprint or result hash differs.",
    );
  }
  return { ...stored, duplicate: true };
}

export type AutonomousWebEvidenceCommitHook = (
  promotion: AutonomousWebEvidencePromotionResult,
) => void;

export class AutonomousWebEvidenceVerifier {
  private readonly actions: ActionRepository;
  private readonly events: EventRepository;
  private readonly now: () => Date;
  private readonly topology: AutonomousReconTopologyProjector;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    manifest: LocalToolCapabilityManifest;
    configuration: AutonomousWebSurfacePlanningConfiguration;
    assertCanonicalAuthority: (action: DurableAction) => void;
    now?: () => Date;
  }>) {
    this.actions = new ActionRepository(options.database);
    this.events = new EventRepository(options.database);
    this.now = options.now ?? (() => new Date());
    this.topology = new AutonomousReconTopologyProjector(options.database);
  }

  private project(promotion: AutonomousWebEvidencePromotionResult): void {
    if (!promotion.observationId || promotion.evidenceIds.length !== 1) return;
    const observation = new OperationalTruthService(
      this.options.database,
      { clock: this.now },
    ).repository.getObservation(promotion.observationId);
    this.topology.project(observation, promotion.evidenceIds);
  }

  private validate(result: AutonomousWebSurfaceResult): Readonly<{
    action: DurableAction;
    authorization: AuthorizedDerivedWebOrigins;
    normalized: Readonly<Record<string, unknown>>;
    outcome: "achieved" | "not_applicable";
  }> {
    const action = this.actions.get(result.actionId);
    this.options.assertCanonicalAuthority(action);
    const phaseActionType = result.phase === "http_metadata"
      ? AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
      : result.phase === "whatweb_fingerprint"
        ? AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
        : AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE;
    const toolId = result.phase === "http_metadata"
      ? AUTONOMOUS_HTTP_METADATA_TOOL_ID
      : result.phase === "whatweb_fingerprint"
        ? AUTONOMOUS_WHATWEB_TOOL_ID
        : AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID;
    const tool = this.options.manifest.resolve(toolId);
    if (result.schemaVersion !== AUTONOMOUS_WEB_SURFACE_RESULT_SCHEMA_VERSION
      || action.status !== "running" || action.actionType !== phaseActionType
      || action.id !== result.actionId || action.fingerprint !== result.actionFingerprint
      || action.missionId !== result.missionId || action.runId !== result.runId
      || action.contractId !== result.contractId || action.target !== result.target
      || !tool || result.children.length !== result.derivedOrigins.length
      || result.children.some(({ origin, toolId: childToolId, inputSha256, result: child }, index) => {
        const expectedOrigin = result.derivedOrigins[index];
        const expectedInputSha256 = expectedOrigin
          ? digestCanonicalJson({
              workspace: this.options.configuration.logicalWorkspace,
              url: expectedOrigin,
            }, { maxBytes: 16 * 1_024, maxDepth: 8 }).sha256
          : null;
        if (!expectedOrigin || origin !== expectedOrigin || childToolId !== toolId
          || inputSha256 !== expectedInputSha256
          || child.invocationId !== autonomousWebChildInvocationId(
            action.id,
            result.phase,
            expectedOrigin,
          )) return true;
        const expectedChildAction: DurableAction = Object.freeze({
          ...action,
          target: expectedOrigin,
        });
        return digestCanonicalJson(autonomousWebChildActionEnvelope(child.action), {
          maxBytes: 1_048_576,
          maxDepth: 64,
        }).sha256 !== digestCanonicalJson(
          autonomousWebChildActionEnvelope(expectedChildAction),
          { maxBytes: 1_048_576, maxDepth: 64 },
        ).sha256;
      })
      || result.outcome !== (result.derivedOrigins.length === 0 ? "not_applicable" : "completed")) {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_web_result_binding_changed",
        "The web result differs from its exact canonical parent action or reviewed physical tool binding.",
      );
    }
    const body = { ...result, resultSha256: undefined } as Record<string, unknown>;
    delete body.resultSha256;
    const unsignedResult = {
      ...body,
      children: result.children.map(({ origin, toolId: childToolId, inputSha256, result: child }) => ({
        origin, toolId: childToolId, inputSha256, invocationId: child.invocationId,
        action: autonomousWebChildActionEnvelope(child.action),
        startedAt: child.startedAt, endedAt: child.endedAt, wallClockMs: child.wallClockMs,
        exitCode: child.exitCode, signal: child.signal, termination: child.termination,
        spawnErrorCode: child.spawnErrorCode, stdout: child.stdout, stderr: child.stderr,
        observedOutputBytes: child.observedOutputBytes, retainedOutputBytes: child.retainedOutputBytes,
        outputSha256: child.outputSha256, outputTruncated: child.outputTruncated,
        executable: child.executable, sandbox: child.sandbox,
      })),
    };
    if (!SHA256.test(result.resultSha256)
      || digestCanonicalJson(unsignedResult, { maxBytes: 64 * 1024 * 1024, maxDepth: 32 }).sha256
        !== result.resultSha256) {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_web_result_hash_changed",
        "The web result no longer matches its immutable composite receipt.",
      );
    }
    const context = this.options.database.prepare(`
      SELECT mission_id, run_id, journey FROM memory_context_packs WHERE id = ?
    `).get(result.contextPackId) as {
      readonly mission_id: string | null;
      readonly run_id: string | null;
      readonly journey: string;
    } | undefined;
    if (!context || context.mission_id !== action.missionId || context.run_id !== action.runId
      || context.journey !== "autonomous") {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_web_context_pack_invalid",
        "The mandatory web-phase Context Pack does not belong to this exact Autonomous run.",
      );
    }
    const authorization = authorizeAutonomousDerivedWebOrigins(
      this.options.database, action, this.options.configuration, result.phase,
    );
    if (authorization.origins.length !== result.derivedOrigins.length
      || authorization.origins.some((origin, index) => origin !== result.derivedOrigins[index])
      || authorization.sourceEvidenceIds.length !== result.sourceEvidenceIds.length
      || authorization.sourceEvidenceIds.some((id, index) => id !== result.sourceEvidenceIds[index])) {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_web_authorization_changed",
        "The derived origins or source evidence changed between dispatch and promotion.",
      );
    }
    const fixedPaths = result.phase === "endpoint_discovery"
      && tool.stagedInput?.kind === "fixed_lines"
      ? tool.stagedInput.lines
      : [];
    if (result.phase === "endpoint_discovery" && fixedPaths.length !== 14) {
      throw new AutonomousWebEvidenceVerificationError(
        "autonomous_endpoint_dictionary_binding_invalid",
        "The endpoint phase is not bound to the exact reviewed fourteen-path staged dictionary.",
      );
    }
    const responses = result.children.map(({ origin, result: child }) => {
      outputIntegrity(child, tool.executable.expectedSha256);
      return result.phase === "http_metadata"
        ? Object.freeze({
            origin,
            request: Object.freeze({
              method: "HEAD",
              url: origin,
              redirectPolicy: "never",
              credentialsSent: false,
            }),
            response: parseHttp(child),
          })
        : result.phase === "whatweb_fingerprint"
          ? Object.freeze({ origin, fingerprint: parseWhatWeb(child) })
          : Object.freeze({ origin, discovery: parseFfuf(child, origin, fixedPaths) });
    });
    return {
      action,
      authorization,
      normalized: Object.freeze({
        schemaVersion: AUTONOMOUS_WEB_EVIDENCE_VERIFIER_SCHEMA_VERSION,
        phase: result.phase,
        parentTarget: action.target,
        derivedOrigins: authorization.origins,
        responses: Object.freeze(responses),
        sourceEvidenceIds: authorization.sourceEvidenceIds,
        contextPackId: result.contextPackId,
        redirectPolicy: "never",
        rawProcessOutputPromoted: false,
        cveApplicability: "not_evaluated",
        resultSha256: result.resultSha256,
      }),
      outcome: authorization.origins.length === 0 ? "not_applicable" : "achieved",
    };
  }

  process(
    result: AutonomousWebSurfaceResult,
    commit?: AutonomousWebEvidenceCommitHook,
  ): AutonomousWebEvidencePromotionResult {
    const key = `${RECEIPT_PREFIX}${createHash("sha256").update(result.actionId).digest("hex")}`;
    const existing = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(key) as { readonly value_json: string } | undefined;
    if (existing) {
      const duplicate = duplicateReceipt(existing.value_json, result);
      return inImmediateTransaction(this.options.database, () => {
        this.project(duplicate);
        commit?.(duplicate);
        return duplicate;
      });
    }
    const verified = this.validate(result);
    return inImmediateTransaction(this.options.database, () => {
      const concurrent = this.options.database.prepare("SELECT value_json FROM settings WHERE key = ?")
        .get(key) as { readonly value_json: string } | undefined;
      if (concurrent) {
        const duplicate = duplicateReceipt(concurrent.value_json, result);
        this.project(duplicate);
        commit?.(duplicate);
        return duplicate;
      }
      // Re-derive after entering the write transaction. No asynchronous target
      // contact occurs between this fence and the immutable evidence commit.
      this.options.assertCanonicalAuthority(verified.action);
      const current = authorizeAutonomousDerivedWebOrigins(
        this.options.database, verified.action, this.options.configuration, result.phase,
      );
      if (current.authorizationSha256 !== verified.authorization.authorizationSha256
        || current.origins.join("\u0000") !== verified.authorization.origins.join("\u0000")
        || current.sourceEvidenceIds.join("\u0000")
          !== verified.authorization.sourceEvidenceIds.join("\u0000")) {
        throw new AutonomousWebEvidenceVerificationError(
          "autonomous_web_authorization_changed",
          "The derived-origin proof changed before evidence commit.",
        );
      }
      const criterion = result.phase === "http_metadata"
        ? this.options.configuration.httpMetadataSuccessCriterion
        : result.phase === "whatweb_fingerprint"
          ? this.options.configuration.whatwebSuccessCriterion
          : this.options.configuration.endpointDiscoverySuccessCriterion;
      if (!criterion) {
        throw new AutonomousWebEvidenceVerificationError(
          "autonomous_endpoint_discovery_not_configured",
          "The endpoint-discovery result has no canonical criterion in the trusted configuration.",
        );
      }
      const criterionId = autonomousSuccessCriterionId(criterion);
      const evidenceType = result.phase === "http_metadata"
        ? AUTONOMOUS_HTTP_METADATA_EVIDENCE_TYPE
        : result.phase === "whatweb_fingerprint"
          ? AUTONOMOUS_WHATWEB_EVIDENCE_TYPE
          : AUTONOMOUS_ENDPOINT_DISCOVERY_EVIDENCE_TYPE;
      const toolName = result.phase === "http_metadata"
        ? AUTONOMOUS_HTTP_METADATA_TOOL_ID
        : result.phase === "whatweb_fingerprint"
          ? AUTONOMOUS_WHATWEB_TOOL_ID
          : AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID;
      const virtualTool = result.phase === "http_metadata"
        ? AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
        : result.phase === "whatweb_fingerprint"
          ? AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
          : AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE;
      const statement = verified.outcome === "not_applicable"
        ? `No HTTP service label was present in the complete verified TCP baseline for ${verified.action.target}; the ${result.phase === "http_metadata" ? "metadata" : result.phase === "whatweb_fingerprint" ? "technology fingerprint" : "endpoint discovery"} phase was not applicable.`
        : result.phase === "http_metadata"
          ? `Ti-Scale received an attributable bounded HTTP metadata response from all ${current.origins.length} evidence-derived origin${current.origins.length === 1 ? "" : "s"}.`
          : result.phase === "whatweb_fingerprint"
            ? `Ti-Scale completed one bounded technology fingerprint check for all ${current.origins.length} responding evidence-derived origin${current.origins.length === 1 ? "" : "s"}.`
            : `Ti-Scale checked the fixed fourteen-path dictionary against all ${current.origins.length} responding evidence-derived origin${current.origins.length === 1 ? "" : "s"}.`;
      if (verified.outcome === "not_applicable") {
        const outcomeBody = {
          schemaVersion: AUTONOMOUS_CRITERION_OUTCOME_PROVENANCE_SCHEMA_VERSION,
          method: "verified_source_evidence_not_applicable",
          missionId: result.missionId,
          runId: result.runId,
          actionId: result.actionId,
          actionFingerprint: result.actionFingerprint,
          criterionId,
          outcome: "not_applicable" as const,
          sourceEvidenceIds: Object.freeze([...current.sourceEvidenceIds]),
          sourceEvidenceContentHashes: Object.freeze(current.sourceEvidenceIds.map((id) => {
            const row = this.options.database.prepare(
              "SELECT content_hash FROM evidence WHERE id = ? AND verification_state = 'verified'",
            ).get(id) as { readonly content_hash: string } | undefined;
            if (!row) throw new AutonomousWebEvidenceVerificationError(
              "autonomous_web_na_source_missing",
              "The not-applicable outcome lost its verified source evidence before commit.",
            );
            return row.content_hash;
          })),
          contextPackId: result.contextPackId,
          resultSha256: result.resultSha256,
        };
        const outcomeReceiptSha256 = digestCanonicalJson(outcomeBody, {
          maxBytes: 2 * 1024 * 1024,
          maxDepth: 24,
        }).sha256;
        const eventId = `event_web_na_${createHash("sha256")
          .update(`${result.actionId}\u0000${criterionId}`).digest("hex").slice(0, 40)}`;
        const createdAt = this.now().toISOString();
        this.events.append({
          id: eventId,
          missionId: result.missionId,
          runId: result.runId,
          journey: "autonomous",
          eventType: "autonomous_criterion_not_applicable",
          occurredAt: result.endedAt,
          actorType: "system",
          actorId: "autonomous-web-evidence-verifier",
          summary: statement,
          payload: {
            ...outcomeBody,
            sourceEvidenceIds: [...outcomeBody.sourceEvidenceIds],
            sourceEvidenceContentHashes: [...outcomeBody.sourceEvidenceContentHashes],
            outcomeReceiptSha256,
          },
          sensitivity: "private",
          contextPackId: result.contextPackId,
        });
        const executionResult: ExecutionResult = Object.freeze({
          actionId: verified.action.id,
          runId: verified.action.runId,
          actionFingerprint: verified.action.fingerprint,
          success: true,
          summary: `${statement} The explicit not-applicable outcome is anchored to prior verified evidence; no web exchange or fingerprint evidence was created.`,
          progress: Object.freeze({
            stepStates: Object.freeze({ [verified.action.stepId]: "completed" as const }),
            evidenceIds: Object.freeze([...current.sourceEvidenceIds]),
          }),
          usage: Object.freeze({ wallClockMs: result.wallClockMs }),
        });
        const persisted: PromotionReceipt = Object.freeze({
          schemaVersion: AUTONOMOUS_WEB_EVIDENCE_VERIFIER_SCHEMA_VERSION,
          actionId: verified.action.id,
          actionFingerprint: verified.action.fingerprint,
          resultSha256: result.resultSha256,
          logRecordId: null,
          observationId: null,
          evidenceIds: Object.freeze([...current.sourceEvidenceIds]),
          executionResult,
        });
        this.options.database.prepare(`
          INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
          VALUES (?, ?, 'private', 1, 'autonomous-web-evidence-verifier', ?)
        `).run(key, digestCanonicalJson(persisted, {
          maxBytes: 2 * 1024 * 1024,
          maxDepth: 24,
        }).canonicalJson, createdAt);
        const promotion = { ...persisted, duplicate: false };
        commit?.(promotion);
        return promotion;
      }
      const truth = new OperationalTruthService(this.options.database, { clock: this.now });
      const plan = this.options.database.prepare("SELECT plan_id FROM plan_steps WHERE id = ?")
        .get(verified.action.stepId) as { readonly plan_id: string };
      const compositeToolCallId = `web_composite_${createHash("sha256")
        .update(result.actionId).digest("hex").slice(0, 40)}`;
      const rawLogRecordIds = result.children.map(({ origin, toolId: childToolId, result: child }) =>
        truth.appendEngagementLog({
          missionId: result.missionId,
          runId: result.runId,
          planId: plan.plan_id,
          stepId: verified.action.stepId,
          actionId: verified.action.id,
          agentId: this.options.configuration.agentId,
          toolCallId: compositeToolCallId,
          severity: child.exitCode === 0 || (result.phase === "http_metadata" && child.exitCode === 22)
            ? "info" : "warning",
          domain: "autonomous_web_surface_raw",
          recordType: "bounded_child_process_output",
          humanSummary: `${childToolId} returned bounded technical output for one evidence-derived origin. Raw output remains an Engagement Log record and was not promoted to evidence.`,
          technicalPayload: {
            origin,
            toolId: childToolId,
            stdout: redactedRawOutput(child.stdout),
            stderr: redactedRawOutput(child.stderr),
            outputSha256: child.outputSha256,
            outputTruncated: child.outputTruncated,
            exitCode: child.exitCode,
            termination: child.termination,
            rawProcessOutputPromoted: false,
          },
          sensitivity: "private",
          occurredAt: child.endedAt,
        }).id);
      const log = truth.appendEngagementLog({
        missionId: result.missionId,
        runId: result.runId,
        planId: plan.plan_id,
        stepId: verified.action.stepId,
        actionId: verified.action.id,
        agentId: this.options.configuration.agentId,
        toolCallId: compositeToolCallId,
        severity: "notice",
        domain: "autonomous_web_surface",
        recordType: "verified_derived_origin_result",
        humanSummary: statement,
        technicalPayload: {
          ...verified.normalized,
          rawLogRecordIds,
        },
        sensitivity: "private",
        occurredAt: result.endedAt,
      });
      const observation = truth.createObservation({
        missionId: result.missionId,
        runId: result.runId,
        stepId: verified.action.stepId,
        observationType: result.phase === "http_metadata"
          ? "http_metadata"
          : result.phase === "whatweb_fingerprint"
            ? "web_technology_fingerprint"
            : "web_endpoint_discovery",
        statement,
        normalizedValue: verified.normalized,
        confidence: result.phase === "http_metadata"
          ? 0.96 : result.phase === "whatweb_fingerprint" ? 0.88 : 0.94,
        verificationState: "corroborated",
        sourceAgentId: this.options.configuration.agentId,
        sourceTool: virtualTool,
        firstSeenAt: result.startedAt,
        lastSeenAt: result.endedAt,
        sensitivity: "private",
        sources: [{
          logRecordId: log.id,
          parserId: "ti-scale.autonomous-web-deterministic-verifier",
          parserVersion: "1.0.0",
        }],
      });
      const content = digestCanonicalJson(verified.normalized, {
        maxBytes: 8 * 1024 * 1024,
        maxDepth: 32,
      });
      const evidenceId = `evidence_web_${createHash("sha256")
        .update(`${result.actionId}\u0000${evidenceType}\u0000${content.sha256}`)
        .digest("hex").slice(0, 40)}`;
      const provenance = digestCanonicalJson({
        schemaVersion: AUTONOMOUS_WEB_EVIDENCE_VERIFIER_SCHEMA_VERSION,
        method: "deterministic_derived_origin_local_process_validation",
        parentActionId: result.actionId,
        parentActionFingerprint: result.actionFingerprint,
        parentTarget: result.target,
        virtualToolId: virtualTool,
        constituentToolIds: [toolName],
        manifestSha256: this.options.manifest.descriptor.manifestSha256,
        sourceEvidenceIds: result.sourceEvidenceIds,
        rawLogRecordIds,
        contextPackId: result.contextPackId,
        resultSha256: result.resultSha256,
        childOutputSha256s: result.children.map(({ result: child }) => child.outputSha256),
        derivedOriginCount: result.derivedOrigins.length,
        redirectPolicy: "never",
        rawProcessOutputPromoted: false,
        cveClaimsCreated: false,
        successCriterionReferences: [{
          schemaVersion: AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION,
          criterionId,
          outcome: verified.outcome,
        }],
      }, { maxBytes: 8 * 1024 * 1024, maxDepth: 32 });
      const createdAt = this.now().toISOString();
      this.options.database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at,
          target, evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          artifact_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'private', 'verified', ?, ?, NULL, ?, ?)
      `).run(
        evidenceId, result.missionId, result.runId, verified.action.stepId, result.actionId,
        `specialist:${this.options.configuration.agentId}`, result.endedAt, result.target,
        evidenceType, content.sha256, provenance.canonicalJson,
        result.phase === "http_metadata"
          ? 0.96 : result.phase === "whatweb_fingerprint" ? 0.88 : 0.94,
        statement, content.canonicalJson, "autonomous-web-evidence-verifier", createdAt,
      );
      this.options.database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'acquired', ?, ?, ?), (?, ?, 'verified', ?, ?, ?)
      `).run(
        `custody_${createHash("sha256").update(`${evidenceId}\u0000acquired`).digest("hex").slice(0, 40)}`,
        evidenceId, this.options.configuration.agentId,
        JSON.stringify({ observationId: observation.id, logRecordId: log.id, resultSha256: result.resultSha256 }),
        result.endedAt,
        `custody_${createHash("sha256").update(`${evidenceId}\u0000verified`).digest("hex").slice(0, 40)}`,
        evidenceId, "autonomous-web-evidence-verifier",
        JSON.stringify({ method: "deterministic_derived_origin_local_process_validation", criterionId, outcome: verified.outcome }),
        createdAt,
      );
      this.topology.project(observation, [evidenceId]);
      const executionResult: ExecutionResult = Object.freeze({
        actionId: verified.action.id,
        runId: verified.action.runId,
        actionFingerprint: verified.action.fingerprint,
        success: true,
        summary: `${statement} Verified evidence was retained with source-evidence lineage and chain of custody.`,
        progress: Object.freeze({
          stepStates: Object.freeze({ [verified.action.stepId]: "completed" as const }),
          evidenceIds: Object.freeze([evidenceId]),
          ...(verified.outcome === "achieved"
            ? { successCriteria: Object.freeze({ [criterionId]: 1 }) }
            : {}),
        }),
        usage: Object.freeze({ wallClockMs: result.wallClockMs }),
      });
      const persisted: PromotionReceipt = Object.freeze({
        schemaVersion: AUTONOMOUS_WEB_EVIDENCE_VERIFIER_SCHEMA_VERSION,
        actionId: verified.action.id,
        actionFingerprint: verified.action.fingerprint,
        resultSha256: result.resultSha256,
        logRecordId: log.id,
        observationId: observation.id,
        evidenceIds: Object.freeze([evidenceId]),
        executionResult,
      });
      this.options.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'private', 1, 'autonomous-web-evidence-verifier', ?)
      `).run(key, digestCanonicalJson(persisted, {
        maxBytes: 8 * 1024 * 1024, maxDepth: 32,
      }).canonicalJson, createdAt);
      const promotion = { ...persisted, duplicate: false };
      commit?.(promotion);
      return promotion;
    });
  }
}
