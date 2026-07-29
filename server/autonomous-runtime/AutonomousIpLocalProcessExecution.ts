import type { ControlPlaneLease } from "../control-plane";
import type { SqliteDatabase } from "../db";
import { OperationalTruthService } from "../intelligence-v24";
import {
  ReviewedNmapTopologyMaterializer,
  ReviewedLocalToolExecutionPort,
  type LocalProcessToolResult,
  type LocalToolCapabilityManifest,
  type LocalToolExecutionOutputRecord,
  type LocalToolExecutionOutputRecorder,
  type ReviewedLocalProcessInvocationAdapter,
} from "../local-tools";
import type { EngagementWorkspaceResolver } from "../system-capabilities";
import type { AutonomousDnsSafeReconConfiguration } from "./AutonomousDnsSafeRecon";
import { AutonomousDnsEvidenceVerifier } from "./AutonomousDnsEvidenceVerifier";
import {
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_IP_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  type AutonomousIpSafeReconConfiguration,
} from "./AutonomousIpSafeRecon";
import { AutonomousIpEvidenceVerifier } from "./AutonomousIpEvidenceVerifier";

export const AUTONOMOUS_IP_LOCAL_PROCESS_EXECUTION_CONTRACT = Object.freeze({
  schemaVersion: "ti-scale.autonomous-local-process-execution.v1" as const,
  adapterId: AUTONOMOUS_IP_SAFE_RECON_ADAPTER_ID,
  executionBinding: "reviewed_local_process" as const,
  directArgv: true as const,
  shell: false as const,
  resultDelivery: "bound_execution_result_sink" as const,
  cancellation: "run_scoped_cooperative" as const,
  publicProviderToolExecution: false as const,
});

export const AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID =
  "ti-scale:autonomous-local-safe-recon" as const;

export const AUTONOMOUS_LOCAL_SAFE_RECON_EXECUTION_CONTRACT = Object.freeze({
  ...AUTONOMOUS_IP_LOCAL_PROCESS_EXECUTION_CONTRACT,
  adapterId: AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID,
});

export class AutonomousIpVerifiedOutputRecorder implements LocalToolExecutionOutputRecorder {
  readonly #nmapTopology: ReviewedNmapTopologyMaterializer;
  readonly #truth: OperationalTruthService;

  constructor(
    private readonly verifier: AutonomousIpEvidenceVerifier,
    database: SqliteDatabase,
  ) {
    this.#nmapTopology = new ReviewedNmapTopologyMaterializer(database);
    this.#truth = new OperationalTruthService(database);
  }

  record(result: LocalProcessToolResult): LocalToolExecutionOutputRecord {
    const outcome = this.verifier.processLocalResult(result);
    if (result.toolId === AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID && outcome.observationId) {
      this.#nmapTopology.materialize(
        this.#truth.repository.getObservation(outcome.observationId),
        { verifiedEvidenceIds: outcome.evidenceIds },
      );
    }
    return Object.freeze({
      logRecordId: outcome.logRecordId,
      observationIds: Object.freeze(outcome.observationId ? [outcome.observationId] : []),
      evidenceCandidateIds: Object.freeze([] as string[]),
      evidenceIds: Object.freeze([...outcome.evidenceIds]),
      artifactIds: Object.freeze([] as string[]),
      executionResult: outcome.executionResult,
    });
  }
}

class AutonomousLocalSafeReconOutputRecorder implements LocalToolExecutionOutputRecorder {
  constructor(
    private readonly dns: AutonomousDnsEvidenceVerifier,
    private readonly ip: AutonomousIpEvidenceVerifier,
    private readonly database: SqliteDatabase,
  ) {}

  record(result: LocalProcessToolResult): LocalToolExecutionOutputRecord {
    if (result.toolId === AUTONOMOUS_IP_LIVENESS_TOOL_ID
      || result.toolId === AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID) {
      return new AutonomousIpVerifiedOutputRecorder(this.ip, this.database).record(result);
    }
    const outcome = this.dns.processLocalResult(result);
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

interface CommonFactoryOptions {
  readonly manifest: LocalToolCapabilityManifest;
  readonly adapter: ReviewedLocalProcessInvocationAdapter;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly now?: () => Date;
}

export interface AutonomousIpLocalProcessExecutionFactoryOptions extends CommonFactoryOptions {
  readonly configuration: AutonomousIpSafeReconConfiguration;
}

export class AutonomousIpLocalProcessExecutionFactory {
  readonly localProcessContract = AUTONOMOUS_IP_LOCAL_PROCESS_EXECUTION_CONTRACT;
  #created = false;
  #port?: ReviewedLocalToolExecutionPort;

  constructor(private readonly options: AutonomousIpLocalProcessExecutionFactoryOptions) {}

  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  }>): ReviewedLocalToolExecutionPort {
    if (this.#created) throw new Error("Autonomous IP local execution factory is single-use");
    const verifier = new AutonomousIpEvidenceVerifier({
      database: input.database,
      manifest: this.options.manifest,
      configuration: this.options.configuration,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    this.#port = new ReviewedLocalToolExecutionPort({
      database: input.database,
      executionJourney: "autonomous",
      manifest: this.options.manifest,
      adapter: this.options.adapter,
      workspaceResolver: this.options.workspaceResolver,
      outputRecorder: new AutonomousIpVerifiedOutputRecorder(verifier, input.database),
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

export interface AutonomousLocalSafeReconExecutionFactoryOptions extends CommonFactoryOptions {
  readonly dnsConfiguration: AutonomousDnsSafeReconConfiguration;
  readonly ipConfiguration: AutonomousIpSafeReconConfiguration;
}

/** One result-aware direct-argv port for the coexisting DNS and IP policies. */
export class AutonomousLocalSafeReconExecutionFactory {
  readonly localProcessContract = AUTONOMOUS_LOCAL_SAFE_RECON_EXECUTION_CONTRACT;
  #created = false;
  #port?: ReviewedLocalToolExecutionPort;

  constructor(private readonly options: AutonomousLocalSafeReconExecutionFactoryOptions) {}

  create(input: Readonly<{
    database: SqliteDatabase;
    assertControlPlaneAuthority: (runId: string) => ControlPlaneLease;
  }>): ReviewedLocalToolExecutionPort {
    if (this.#created) throw new Error("Autonomous local Safe Recon execution factory is single-use");
    const dns = new AutonomousDnsEvidenceVerifier({
      database: input.database,
      manifest: this.options.manifest,
      configuration: this.options.dnsConfiguration,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    const ip = new AutonomousIpEvidenceVerifier({
      database: input.database,
      manifest: this.options.manifest,
      configuration: this.options.ipConfiguration,
      ...(this.options.now ? { now: this.options.now } : {}),
    });
    this.#port = new ReviewedLocalToolExecutionPort({
      database: input.database,
      executionJourney: "autonomous",
      manifest: this.options.manifest,
      adapter: this.options.adapter,
      workspaceResolver: this.options.workspaceResolver,
      outputRecorder: new AutonomousLocalSafeReconOutputRecorder(dns, ip, input.database),
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
