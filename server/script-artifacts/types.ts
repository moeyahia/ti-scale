import type { Sensitivity } from "../intelligence-v24/types";

export type ScriptLanguage =
  | "bash"
  | "c"
  | "cpp"
  | "csharp"
  | "go"
  | "java"
  | "javascript"
  | "lua"
  | "perl"
  | "powershell"
  | "python"
  | "ruby"
  | "rust"
  | "sql"
  | "typescript";

export type ScriptRiskClass = "low" | "medium" | "high" | "critical";
export type ScriptValidationState = "unvalidated" | "linted" | "tested" | "approved" | "rejected";
export type ScriptTestStatus = "not_run" | "passed" | "failed";

export interface ScriptParameter {
  readonly name: string;
  readonly description: string;
  readonly required: boolean;
  /** Describes whether the value is a reference to sensitive runtime input. Values are never retained here. */
  readonly sensitivity: "ordinary" | "secret_reference";
}

export interface ScriptExpectedOutput {
  readonly label: string;
  readonly description: string;
  readonly successRecognition: string;
  readonly failureRecognition: string;
}

export interface ScriptRequirements {
  readonly prerequisites: readonly string[];
  readonly dependencies: readonly string[];
}

export interface ScriptTouches {
  readonly files: readonly string[];
  readonly network: readonly string[];
  readonly services: readonly string[];
}

export interface ScriptRiskDocumentation {
  readonly riskClass: ScriptRiskClass;
  readonly sideEffects: readonly string[];
  readonly reversibility: string;
}

export interface ScriptTestRecord {
  readonly name: string;
  readonly status: ScriptTestStatus;
  readonly summary: string;
}

export interface ScriptValidationDocumentation {
  readonly state: ScriptValidationState;
  readonly summary: string;
  readonly tests: readonly ScriptTestRecord[];
  readonly testArtifactId?: string;
}

export interface ScriptProvenance {
  readonly origin: "operator_authored" | "agent_generated" | "imported" | "modified";
  readonly explanation: string;
  readonly sourceRefs: readonly string[];
  readonly authorAgentId?: string;
}

export interface ScriptVersionDiff {
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
  /** Safe relative source path, used as the immutable version-chain name. */
  readonly name: string;
  readonly language: ScriptLanguage;
  readonly version: number;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly mediaType: string;
  readonly sensitivity: Sensitivity;
  readonly laymanExplanation: string;
  readonly technicalPurpose: string;
  readonly inputs: readonly ScriptParameter[];
  readonly expectedOutputs: readonly ScriptExpectedOutput[];
  readonly requirements: ScriptRequirements;
  readonly touches: ScriptTouches;
  readonly risk: ScriptRiskDocumentation;
  readonly cleanupNotes: string;
  readonly secretsHandling: string;
  readonly evidenceExpectations: readonly string[];
  readonly validation: ScriptValidationDocumentation;
  readonly provenance: ScriptProvenance & {
    readonly createdBy: string;
    readonly createdByType: "operator" | "agent" | "worker" | "system";
  };
  readonly diff: ScriptVersionDiff;
  readonly storageUri: string;
  readonly createdBy: string;
  readonly createdAt: string;
}

export interface ScriptArtifactDetail extends ScriptArtifactSummary {
  /** Immutable source loaded from the content-addressed source store. */
  readonly source: string;
}

export interface ScriptArtifactDocumentationInput {
  readonly language: ScriptLanguage;
  readonly source: string;
  readonly laymanExplanation: string;
  readonly technicalPurpose: string;
  readonly inputs: readonly ScriptParameter[];
  readonly expectedOutputs: readonly ScriptExpectedOutput[];
  readonly prerequisites: readonly string[];
  readonly dependencies: readonly string[];
  readonly touches: ScriptTouches;
  readonly sideEffects: readonly string[];
  readonly riskClass: ScriptRiskClass;
  readonly reversibility: string;
  readonly cleanupNotes: string;
  readonly secretsHandling: string;
  readonly evidenceExpectations: readonly string[];
  readonly validation: ScriptValidationDocumentation;
  readonly provenance: ScriptProvenance;
  readonly sensitivity: Sensitivity;
}

export interface CreateScriptArtifactInput extends ScriptArtifactDocumentationInput {
  readonly missionId: string;
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly attackAttemptId?: string;
  readonly targetNodeId?: string;
  readonly name: string;
}

export interface CreateScriptVersionInput extends ScriptArtifactDocumentationInput {
  readonly scriptArtifactId: string;
  readonly expectedVersion: number;
  readonly changeSummary: string;
}

export interface ScriptArtifactListFilter {
  readonly missionId: string;
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly targetNodeId?: string;
  readonly language?: ScriptLanguage;
  readonly name?: string;
  readonly limit?: number;
}

export interface ScriptArtifactActor {
  readonly id: string;
  readonly type: "operator" | "agent" | "worker" | "system";
}

export class ScriptArtifactError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly category: string = "invalid_input",
    readonly status: number = 400,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "ScriptArtifactError";
  }
}
