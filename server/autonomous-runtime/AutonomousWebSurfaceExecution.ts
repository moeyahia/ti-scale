import { createHash } from "node:crypto";
import type { DurableAction } from "../orchestration";
import {
  LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
  LocalProcessToolExecutionError,
  type LocalProcessToolInvocation,
  type LocalProcessToolResult,
  type LocalProcessToolResultSink,
  type LocalToolCapabilityManifest,
  type ReviewedLocalProcessInvocationAdapter,
} from "../local-tools";
import { digestCanonicalJson } from "../mcp";
import type { EngagementWorkspaceResolver } from "../system-capabilities";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  type AutonomousWebSurfacePlanningConfiguration,
} from "./AutonomousWebSurfaceBaseline";
import {
  verifyAutonomousDerivedWebOriginAuthorization,
  type AuthorizedDerivedWebOrigins,
} from "./AutonomousWebOriginAuthorization";

export const AUTONOMOUS_WEB_SURFACE_RESULT_SCHEMA_VERSION =
  "ti-scale.autonomous-web-surface-result.v2" as const;

export type AutonomousWebSurfacePhase =
  | "http_metadata"
  | "whatweb_fingerprint"
  | "endpoint_discovery";

export interface AutonomousWebSurfaceChildResult {
  readonly origin: string;
  readonly toolId:
    | typeof AUTONOMOUS_HTTP_METADATA_TOOL_ID
    | typeof AUTONOMOUS_WHATWEB_TOOL_ID
    | typeof AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID;
  readonly inputSha256: string;
  readonly result: LocalProcessToolResult;
}

export interface AutonomousWebSurfaceResult {
  readonly schemaVersion: typeof AUTONOMOUS_WEB_SURFACE_RESULT_SCHEMA_VERSION;
  readonly phase: AutonomousWebSurfacePhase;
  readonly missionId: string;
  readonly runId: string;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly contractId: string;
  readonly target: string;
  readonly derivedOrigins: readonly string[];
  readonly sourceEvidenceIds: readonly string[];
  readonly outcome: "completed" | "not_applicable";
  readonly contextPackId: string;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly wallClockMs: number;
  readonly children: readonly AutonomousWebSurfaceChildResult[];
  readonly resultSha256: string;
}

export interface ReviewedAutonomousWebSurfaceInvocationAdapter
  extends ReviewedLocalProcessInvocationAdapter {}

interface PendingResult {
  readonly resolve: (result: LocalProcessToolResult) => void;
  readonly reject: (error: Error) => void;
}

const AUTONOMOUS_WEB_CHILD_STAGE_SCHEMA_VERSION =
  "ti-scale.autonomous-web-child-contact-stage.v2" as const;

function childStageKey(
  actionId: string,
  phase: AutonomousWebSurfacePhase,
  origin: string,
): string {
  return `runtime.autonomous-web-child.${createHash("sha256")
    .update(`${actionId}\u0000${phase}\u0000${origin}`, "utf8").digest("hex")}`;
}

export function autonomousWebChildInvocationId(
  actionId: string,
  phase: AutonomousWebSurfacePhase,
  origin: string,
): string {
  return `web_surface_${createHash("sha256")
    .update(`${actionId}\u0000${phase}\u0000${origin}`, "utf8").digest("hex").slice(0, 40)}`;
}

/**
 * Stable, complete action identity retained in every composite child receipt.
 * The URL-bound child is an in-memory clone of the canonical parent; no field
 * other than `target` may change across the reviewed process boundary.
 */
export function autonomousWebChildActionEnvelope(
  action: DurableAction,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: action.id,
    missionId: action.missionId,
    runId: action.runId,
    stepId: action.stepId,
    actionType: action.actionType,
    actionClass: action.actionClass,
    fingerprint: action.fingerprint,
    arguments: action.arguments,
    target: action.target,
    kind: action.kind,
    intentSummary: action.intentSummary,
    status: action.status,
    idempotent: action.idempotent,
    destructive: action.destructive,
    guidedDecisionId: action.guidedDecisionId,
    contractId: action.contractId,
    contextPackId: action.contextPackId,
    resultSummary: action.resultSummary,
    errorCategory: action.errorCategory,
    retryCount: action.retryCount,
    progressSignature: action.progressSignature,
    createdAt: action.createdAt,
    startedAt: action.startedAt,
    endedAt: action.endedAt,
  });
}

function sameChildAction(actual: DurableAction, expected: DurableAction): boolean {
  return digestCanonicalJson(autonomousWebChildActionEnvelope(actual), {
    maxBytes: 1_048_576,
    maxDepth: 64,
  }).sha256 === digestCanonicalJson(autonomousWebChildActionEnvelope(expected), {
    maxBytes: 1_048_576,
    maxDepth: 64,
  }).sha256;
}

function unsigned(result: Omit<AutonomousWebSurfaceResult, "resultSha256">): Readonly<Record<string, unknown>> {
  return {
    ...result,
    children: result.children.map(({ origin, toolId, inputSha256, result: child }) => ({
      origin,
      toolId,
      inputSha256,
      invocationId: child.invocationId,
      action: autonomousWebChildActionEnvelope(child.action),
      startedAt: child.startedAt,
      endedAt: child.endedAt,
      wallClockMs: child.wallClockMs,
      exitCode: child.exitCode,
      signal: child.signal,
      termination: child.termination,
      spawnErrorCode: child.spawnErrorCode,
      stdout: child.stdout,
      stderr: child.stderr,
      observedOutputBytes: child.observedOutputBytes,
      retainedOutputBytes: child.retainedOutputBytes,
      outputSha256: child.outputSha256,
      outputTruncated: child.outputTruncated,
      executable: child.executable,
      sandbox: child.sandbox,
    })),
  };
}

export function autonomousWebSurfaceResultReceiptSha256(
  result: Omit<AutonomousWebSurfaceResult, "resultSha256">,
): string {
  return digestCanonicalJson(unsigned(result), {
    maxBytes: 64 * 1024 * 1024,
    maxDepth: 32,
  }).sha256;
}

/** Executes exact derived origins through a private child-action channel. */
export class AutonomousWebSurfaceExecution {
  private readonly pending = new Map<string, PendingResult>();
  private readonly unbind: () => void;
  private readonly now: () => Date;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    manifest: LocalToolCapabilityManifest;
    configuration: AutonomousWebSurfacePlanningConfiguration;
    adapter: ReviewedAutonomousWebSurfaceInvocationAdapter;
    workspaceResolver: EngagementWorkspaceResolver;
    assertOriginAuthority: (input: Readonly<{
      action: DurableAction;
      authorization: AuthorizedDerivedWebOrigins;
      origin: string;
      originIndex: number;
    }>) => AuthorizedDerivedWebOrigins;
    now?: () => Date;
  }>) {
    this.now = options.now ?? (() => new Date());
    const unbind = options.adapter.bindResultSink({
      acceptLocalProcessToolResult: (result) => this.accept(result),
    });
    this.unbind = typeof unbind === "function" ? unbind : () => undefined;
  }

  private async accept(result: LocalProcessToolResult): Promise<void> {
    const pending = this.pending.get(result.invocationId);
    if (!pending) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_result_unexpected",
        "A web-surface process result did not match an active derived-origin invocation.",
      );
    }
    pending.resolve(result);
  }

  private dispatchAndWait(
    invocation: LocalProcessToolInvocation,
    signal: AbortSignal,
  ): Promise<LocalProcessToolResult> {
    return new Promise((resolve, reject) => {
      const id = invocation.invocationId;
      if (this.pending.has(id)) {
        reject(new Error("Duplicate web-surface child invocation"));
        return;
      }
      let settled = false;
      let aborting = false;
      const finish = (callback: () => void): void => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", abort);
        this.pending.delete(id);
        callback();
      };
      const abort = (): void => {
        if (aborting || settled) return;
        aborting = true;
        void this.options.adapter.cancelRun(
          invocation.action.runId,
          "Autonomous web child cancelled before a correlated result was delivered.",
        ).finally(() => finish(() => reject(new LocalProcessToolExecutionError(
          "autonomous_web_cancelled",
          "The run was cancelled after the bounded web process group finished stopping.",
        ))));
      };
      this.pending.set(id, {
        resolve: (result) => finish(() => resolve(result)),
        reject: (error) => finish(() => reject(error)),
      });
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) {
        abort();
        return;
      }
      void this.options.adapter.dispatch(invocation, signal).catch((error) => {
        // A process adapter commonly rejects its dispatch promise as soon as
        // the AbortSignal fires. Cleanup still owns settlement: cancellation
        // may resolve only after the complete process group has stopped.
        if (aborting || signal.aborted) return;
        finish(() => reject(error instanceof Error
          ? error : new Error("Web-surface dispatch failed")));
      });
    });
  }

  private authorizeAndStageContact(input: Readonly<{
    action: DurableAction;
    authorization: AuthorizedDerivedWebOrigins;
    origin: string;
    originIndex: number;
    toolId:
      | typeof AUTONOMOUS_HTTP_METADATA_TOOL_ID
      | typeof AUTONOMOUS_WHATWEB_TOOL_ID
      | typeof AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID;
    invocationId: string;
    inputSha256: string;
    contextPackId: string;
  }>): void {
    inImmediateTransaction(this.options.database, () => {
      const current = this.options.assertOriginAuthority({
        action: input.action,
        authorization: input.authorization,
        origin: input.origin,
        originIndex: input.originIndex,
      });
      if (current.authorizationSha256 !== input.authorization.authorizationSha256
        || current.origins[input.originIndex] !== input.origin) {
        throw new LocalProcessToolExecutionError(
          "autonomous_web_origin_authority_changed",
          "The canonical lease, contract, source evidence, or exact derived origin changed before contact.",
        );
      }
      const key = childStageKey(input.action.id, input.authorization.phase, input.origin);
      const existing = this.options.database.prepare("SELECT 1 FROM settings WHERE key = ?")
        .get(key);
      if (existing) {
        throw new LocalProcessToolExecutionError(
          "autonomous_web_child_contact_already_staged",
          "This exact derived origin already has a durable contact intent or result. Ti-Scale will not contact it again implicitly after a restart.",
        );
      }
      const startedAt = this.now().toISOString();
      this.options.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'private', 1, 'autonomous-web-surface-execution', ?)
      `).run(key, digestCanonicalJson({
        schemaVersion: AUTONOMOUS_WEB_CHILD_STAGE_SCHEMA_VERSION,
        state: "contacting",
        actionId: input.action.id,
        actionFingerprint: input.action.fingerprint,
        phase: input.authorization.phase,
        origin: input.origin,
        originIndex: input.originIndex,
        toolId: input.toolId,
        invocationId: input.invocationId,
        inputSha256: input.inputSha256,
        authorizationSha256: input.authorization.authorizationSha256,
        contextPackId: input.contextPackId,
        startedAt,
      }, { maxBytes: 128 * 1_024, maxDepth: 16 }).canonicalJson, startedAt);
    });
  }

  private stageCompletedResult(input: Readonly<{
    action: DurableAction;
    authorization: AuthorizedDerivedWebOrigins;
    origin: string;
    originIndex: number;
    inputSha256: string;
    result: LocalProcessToolResult;
  }>): void {
    const key = childStageKey(input.action.id, input.authorization.phase, input.origin);
    const endedAt = this.now().toISOString();
    const resultReceiptSha256 = digestCanonicalJson({
      invocationId: input.result.invocationId,
      toolId: input.result.toolId,
      action: autonomousWebChildActionEnvelope(input.result.action),
      inputSha256: input.inputSha256,
      exitCode: input.result.exitCode,
      signal: input.result.signal,
      termination: input.result.termination,
      spawnErrorCode: input.result.spawnErrorCode,
      outputSha256: input.result.outputSha256,
      outputTruncated: input.result.outputTruncated,
      observedOutputBytes: input.result.observedOutputBytes,
      retainedOutputBytes: input.result.retainedOutputBytes,
      sourceSha256: input.result.executable.sourceSha256,
      snapshotSha256: input.result.executable.snapshotSha256,
    }, { maxBytes: 128 * 1_024, maxDepth: 16 }).sha256;
    const changed = this.options.database.prepare(`
      UPDATE settings SET value_json = ?, version = version + 1,
        updated_by = 'autonomous-web-surface-execution', updated_at = ?
      WHERE key = ? AND json_extract(value_json, '$.state') = 'contacting'
        AND json_extract(value_json, '$.actionFingerprint') = ?
        AND json_extract(value_json, '$.authorizationSha256') = ?
        AND json_extract(value_json, '$.inputSha256') = ?
    `).run(digestCanonicalJson({
      schemaVersion: AUTONOMOUS_WEB_CHILD_STAGE_SCHEMA_VERSION,
      state: "completed",
      actionId: input.action.id,
      actionFingerprint: input.action.fingerprint,
      phase: input.authorization.phase,
      origin: input.origin,
      originIndex: input.originIndex,
      toolId: input.result.toolId,
      invocationId: input.result.invocationId,
      inputSha256: input.inputSha256,
      authorizationSha256: input.authorization.authorizationSha256,
      outputSha256: input.result.outputSha256,
      resultReceiptSha256,
      endedAt,
    }, { maxBytes: 128 * 1_024, maxDepth: 16 }).canonicalJson,
    endedAt, key, input.action.fingerprint, input.authorization.authorizationSha256,
    input.inputSha256).changes;
    if (changed !== 1) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_child_stage_changed",
        "The durable per-origin contact stage changed before its bounded result could be recorded.",
      );
    }
  }

  async execute(input: Readonly<{
    action: DurableAction;
    authorization: AuthorizedDerivedWebOrigins;
    contextPackId: string;
  }>, signal: AbortSignal): Promise<AutonomousWebSurfaceResult> {
    if (!input.action.contractId) {
      throw new LocalProcessToolExecutionError(
        "autonomous_web_contract_missing",
        "The derived-origin action is not bound to a confirmed Autonomous contract.",
      );
    }
    const authorization = verifyAutonomousDerivedWebOriginAuthorization(
      this.options.database,
      input.action,
      this.options.configuration,
      input.authorization,
    );
    const workspace = await this.options.workspaceResolver.resolve(
      this.options.configuration.logicalWorkspace,
    );
    if (workspace.status !== "resolved" || !workspace.resolvedPath) {
      throw new LocalProcessToolExecutionError(`workspace_${workspace.code}`, workspace.explanation);
    }
    const startedAt = this.now();
    const toolId = authorization.phase === "http_metadata"
      ? AUTONOMOUS_HTTP_METADATA_TOOL_ID
      : authorization.phase === "whatweb_fingerprint"
        ? AUTONOMOUS_WHATWEB_TOOL_ID
        : AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID;
    const children: AutonomousWebSurfaceChildResult[] = [];
    for (const [originIndex, origin] of authorization.origins.entries()) {
      if (signal.aborted) {
        throw new LocalProcessToolExecutionError(
          "autonomous_web_cancelled",
          "The run was cancelled before the next derived origin was contacted.",
        );
      }
      // This derived child is deliberately never persisted as an independent
      // action. The parent remains the exact authorized IP. The raw adapter
      // sees a URL-bound clone only inside this sealed, revalidated channel.
      const childAction: DurableAction = Object.freeze({ ...input.action, target: origin });
      const parameters = Object.freeze({
        workspace: this.options.configuration.logicalWorkspace,
        url: origin,
      });
      const id = autonomousWebChildInvocationId(input.action.id, authorization.phase, origin);
      const invocation: LocalProcessToolInvocation = Object.freeze({
        schemaVersion: LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
        invocationId: id,
        action: childAction,
        toolId,
        parameters,
        inputSha256: digestCanonicalJson(parameters, {
          maxBytes: 16 * 1_024,
          maxDepth: 8,
        }).sha256,
        resolvedWorkspacePath: workspace.resolvedPath,
      });
      this.authorizeAndStageContact({
        action: input.action,
        authorization,
        origin,
        originIndex,
        toolId,
        invocationId: id,
        inputSha256: invocation.inputSha256,
        contextPackId: input.contextPackId,
      });
      const result = await this.dispatchAndWait(invocation, signal);
      if (result.invocationId !== id || result.toolId !== toolId
        || !sameChildAction(result.action, childAction)) {
        throw new LocalProcessToolExecutionError(
          "autonomous_web_result_correlation_mismatch",
          "A web-surface child result changed its exact origin, tool, or complete parent action envelope.",
        );
      }
      this.stageCompletedResult({
        action: input.action,
        authorization,
        origin,
        originIndex,
        inputSha256: invocation.inputSha256,
        result,
      });
      children.push(Object.freeze({
        origin,
        toolId,
        inputSha256: invocation.inputSha256,
        result,
      }));
    }
    const endedAt = this.now();
    const body = Object.freeze({
      schemaVersion: AUTONOMOUS_WEB_SURFACE_RESULT_SCHEMA_VERSION,
      phase: authorization.phase,
      missionId: input.action.missionId,
      runId: input.action.runId,
      actionId: input.action.id,
      actionFingerprint: input.action.fingerprint,
      contractId: input.action.contractId,
      target: input.action.target,
      derivedOrigins: Object.freeze([...authorization.origins]),
      sourceEvidenceIds: Object.freeze([...authorization.sourceEvidenceIds]),
      outcome: authorization.outcome === "not_applicable" ? "not_applicable" : "completed",
      contextPackId: input.contextPackId,
      startedAt: startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
      wallClockMs: Math.max(0, endedAt.getTime() - startedAt.getTime()),
      children: Object.freeze(children),
    });
    return Object.freeze({
      ...body,
      resultSha256: autonomousWebSurfaceResultReceiptSha256(body),
    });
  }

  cancelRun(runId: string, reason: string): Promise<void> {
    return this.options.adapter.cancelRun(runId, reason);
  }

  close(): void {
    if (this.pending.size > 0) {
      for (const pending of this.pending.values()) {
        pending.reject(new Error("Autonomous web-surface executor closed"));
      }
      this.pending.clear();
    }
    this.unbind();
  }
}
