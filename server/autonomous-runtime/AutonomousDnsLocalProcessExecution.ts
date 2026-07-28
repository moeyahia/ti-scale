import type { ControlPlaneLease } from "../control-plane";
import type { SqliteDatabase } from "../db";
import {
  ReviewedLocalToolExecutionPort,
  type LocalProcessToolResult,
  type LocalToolCapabilityManifest,
  type LocalToolExecutionOutputRecord,
  type LocalToolExecutionOutputRecorder,
  type ReviewedLocalProcessInvocationAdapter,
} from "../local-tools";
import type { EngagementWorkspaceResolver } from "../system-capabilities";
import {
  AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID,
  type AutonomousDnsSafeReconConfiguration,
} from "./AutonomousDnsSafeRecon";
import { AutonomousDnsEvidenceVerifier } from "./AutonomousDnsEvidenceVerifier";

export const AUTONOMOUS_DNS_LOCAL_PROCESS_EXECUTION_CONTRACT = Object.freeze({
  schemaVersion: "ti-scale.autonomous-local-process-execution.v1" as const,
  adapterId: AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID,
  executionBinding: "reviewed_local_process" as const,
  directArgv: true as const,
  shell: false as const,
  resultDelivery: "bound_execution_result_sink" as const,
  cancellation: "run_scoped_cooperative" as const,
  publicProviderToolExecution: false as const,
});

/**
 * Bridges the exact local process result into the DNS-specific evidence
 * verifier. Raw stdout remains an Engagement Log; only the verifier may return
 * an immutable evidence ID and criteria-aware execution result.
 */
export class AutonomousDnsVerifiedOutputRecorder implements LocalToolExecutionOutputRecorder {
  constructor(private readonly verifier: AutonomousDnsEvidenceVerifier) {}

  record(result: LocalProcessToolResult): LocalToolExecutionOutputRecord {
    const outcome = this.verifier.processLocalResult(result);
    return Object.freeze({
      logRecordId: outcome.logRecordId,
      observationIds: Object.freeze(outcome.observationId ? [outcome.observationId] : []),
      evidenceCandidateIds: Object.freeze([] as string[]),
      evidenceIds: Object.freeze(outcome.evidenceId ? [outcome.evidenceId] : []),
      artifactIds: Object.freeze([] as string[]),
      executionResult: outcome.executionResult,
    });
  }
}

export interface AutonomousDnsLocalProcessExecutionFactoryOptions {
  readonly manifest: LocalToolCapabilityManifest;
  readonly configuration: AutonomousDnsSafeReconConfiguration;
  readonly adapter: ReviewedLocalProcessInvocationAdapter;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly now?: () => Date;
}

/**
 * Single-use factory for the truthful direct-argv Autonomous DNS route. It
 * deliberately exposes no MCP execution identity: an MCP tools/list receipt,
 * when required by activation policy, remains advisory capability inventory.
 */
export class AutonomousDnsLocalProcessExecutionFactory {
  readonly localProcessContract = AUTONOMOUS_DNS_LOCAL_PROCESS_EXECUTION_CONTRACT;
  readonly #configuration: AutonomousDnsSafeReconConfiguration;
  #created = false;
  #port?: ReviewedLocalToolExecutionPort;

  constructor(private readonly options: AutonomousDnsLocalProcessExecutionFactoryOptions) {
    this.#configuration = options.configuration;
  }

  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  }>): ReviewedLocalToolExecutionPort {
    if (this.#created) throw new Error("Autonomous DNS local execution factory is single-use");
    const verifier = new AutonomousDnsEvidenceVerifier({
      database: input.database,
      manifest: this.options.manifest,
      configuration: this.#configuration,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    this.#port = new ReviewedLocalToolExecutionPort({
      database: input.database,
      executionJourney: "autonomous",
      manifest: this.options.manifest,
      adapter: this.options.adapter,
      workspaceResolver: this.options.workspaceResolver,
      outputRecorder: new AutonomousDnsVerifiedOutputRecorder(verifier),
      assertControlPlaneAuthority: input.assertControlPlaneAuthority,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    this.#created = true;
    return this.#port;
  }

  close(): void {
    this.#port?.close();
    this.#port = undefined;
  }
}
