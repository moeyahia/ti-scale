import type { OperationalSensitivity } from "./operationalTruth";

export type ScriptLanguage =
  | "bash" | "c" | "cpp" | "csharp" | "go" | "java" | "javascript" | "lua"
  | "perl" | "powershell" | "python" | "ruby" | "rust" | "sql" | "typescript";
export type ScriptRiskClass = "low" | "medium" | "high" | "critical";
export type ScriptValidationState = "unvalidated" | "linted" | "tested" | "approved" | "rejected";

export interface ScriptParameter {
  readonly name: string;
  readonly description: string;
  readonly required: boolean;
  readonly sensitivity: "ordinary" | "secret_reference";
}

export interface ScriptExpectedOutput {
  readonly label: string;
  readonly description: string;
  readonly successRecognition: string;
  readonly failureRecognition: string;
}

export interface ScriptArtifactSummary {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly attackAttemptId?: string;
  readonly targetNodeId?: string;
  readonly artifactId: string;
  readonly name: string;
  readonly language: ScriptLanguage;
  readonly version: number;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly mediaType: string;
  readonly sensitivity: OperationalSensitivity;
  readonly laymanExplanation: string;
  readonly technicalPurpose: string;
  readonly inputs: readonly ScriptParameter[];
  readonly expectedOutputs: readonly ScriptExpectedOutput[];
  readonly requirements: {
    readonly prerequisites: readonly string[];
    readonly dependencies: readonly string[];
  };
  readonly touches: {
    readonly files: readonly string[];
    readonly network: readonly string[];
    readonly services: readonly string[];
  };
  readonly risk: {
    readonly riskClass: ScriptRiskClass;
    readonly sideEffects: readonly string[];
    readonly reversibility: string;
  };
  readonly cleanupNotes: string;
  readonly secretsHandling: string;
  readonly evidenceExpectations: readonly string[];
  readonly validation: {
    readonly state: ScriptValidationState;
    readonly summary: string;
    readonly tests: readonly {
      readonly name: string;
      readonly status: "not_run" | "passed" | "failed";
      readonly summary: string;
    }[];
    readonly testArtifactId?: string;
  };
  readonly provenance: {
    readonly origin: "operator_authored" | "agent_generated" | "imported" | "modified";
    readonly explanation: string;
    readonly sourceRefs: readonly string[];
    readonly authorAgentId?: string;
    readonly createdBy: string;
    readonly createdByType: "operator" | "agent" | "worker" | "system";
  };
  readonly diff: {
    readonly previousScriptArtifactId?: string;
    readonly fromVersion?: number;
    readonly toVersion: number;
    readonly previousContentHash?: string;
    readonly contentHash: string;
    readonly sourceChanged: boolean;
    readonly changedFields: readonly string[];
    readonly commonPrefixLines: number;
    readonly commonSuffixLines: number;
    readonly removedLineCount: number;
    readonly addedLineCount: number;
    readonly changeSummary: string;
  };
  readonly storageUri: string;
  readonly createdBy: string;
  readonly createdAt: string;
}

export interface ScriptArtifactDetail extends ScriptArtifactSummary {
  readonly source: string;
}

export interface ScriptArtifactList {
  readonly schemaVersion: "2.4";
  readonly items: readonly ScriptArtifactSummary[];
}

export interface ScriptArtifactDetailResponse {
  readonly schemaVersion: "2.4";
  readonly record: ScriptArtifactDetail;
}

export interface ScriptArtifactFilter {
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly targetNodeId?: string;
  readonly language?: ScriptLanguage;
  readonly name?: string;
  readonly limit?: number;
}
