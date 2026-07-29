import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalJson, deepFreeze, sha256, type JsonValue } from "./canonical";

export interface ExperimentIntegrityPayload {
  readonly experimentId: string;
  readonly charterHash: string;
  readonly strategyHashes: {
    readonly baseline: string;
    readonly candidate: string;
  };
  readonly evaluatorVersion: string;
  readonly evaluatorHash: string;
  readonly benchmarkSnapshotHash: string;
  readonly containerImageDigest: string;
  readonly executionEnvironment?: {
    readonly kind: "local_bwrap" | "oci_container";
    readonly identityHash: string;
  };
  readonly toolManifestHash: string;
  readonly providerModel: {
    readonly providerId: string;
    readonly modelId: string;
    readonly promptTemplateHash: string;
  } | null;
  readonly contextPackIds: readonly string[];
  readonly randomSeeds: readonly string[];
  readonly eventHash: string;
  readonly evidenceHash: string;
  readonly metricsHash: string;
  readonly exposureReceiptIds: readonly string[];
  readonly evaluationStage:
    | "development"
    | "validation"
    | "hidden_holdout"
    | "shadow"
    | "canary";
  readonly evaluationAction:
    | "development_pass"
    | "development_fail"
    | "validation_pass"
    | "validation_fail"
    | "hidden_holdout_pass"
    | "hidden_holdout_fail"
    | "shadow_pass"
    | "shadow_fail"
    | "canary_pass"
    | "canary_fail";
  readonly evaluationResult: "pass" | "fail";
  readonly evaluationAttemptId: string;
  readonly hardGateFailures: readonly string[];
  readonly signedAt: string;
}

export interface ExperimentIntegrityReceipt extends ExperimentIntegrityPayload {
  readonly id: string;
  readonly algorithm: "hmac-sha256";
  readonly signature: string;
}

export interface ExpectedIntegrityBindings {
  readonly experimentId?: string;
  readonly charterHash?: string;
  readonly evaluatorHash?: string;
  readonly benchmarkSnapshotHash?: string;
  readonly baselineStrategyHash?: string;
  readonly candidateStrategyHash?: string;
  readonly evaluatorVersion?: string;
  readonly containerImageDigest?: string;
  readonly executionEnvironmentKind?: "local_bwrap" | "oci_container";
  readonly executionEnvironmentIdentityHash?: string;
  readonly toolManifestHash?: string;
  readonly providerId?: string | null;
  readonly modelId?: string | null;
  readonly promptTemplateHash?: string | null;
  readonly contextPackIds?: readonly string[];
  readonly randomSeeds?: readonly string[];
  readonly eventHash?: string;
  readonly evidenceHash?: string;
  readonly metricsHash?: string;
  readonly exposureReceiptIds?: readonly string[];
  readonly evaluationStage?: ExperimentIntegrityPayload["evaluationStage"];
  readonly evaluationAction?: ExperimentIntegrityPayload["evaluationAction"];
  readonly evaluationResult?: ExperimentIntegrityPayload["evaluationResult"];
  readonly evaluationAttemptId?: string;
  readonly hardGateFailures?: readonly string[];
}

export interface IntegrityVerification {
  readonly valid: boolean;
  readonly reasons: readonly string[];
}

function payloadFromReceipt(receipt: ExperimentIntegrityReceipt): ExperimentIntegrityPayload {
  const {
    id: _id,
    algorithm: _algorithm,
    signature: _signature,
    ...payload
  } = receipt;
  return payload;
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function payloadValidationReasons(payload: ExperimentIntegrityPayload): string[] {
  const reasons: string[] = [];
  const requiredText: readonly [string, string][] = [
    ["experiment ID", payload.experimentId],
    ["evaluator version", payload.evaluatorVersion],
  ];
  for (const [label, value] of requiredText) {
    if (typeof value !== "string" || value.trim().length === 0) reasons.push(`Integrity ${label} is missing.`);
  }
  const hashes: readonly [string, unknown][] = [
    ["charter", payload.charterHash],
    ["baseline strategy", payload.strategyHashes?.baseline],
    ["candidate strategy", payload.strategyHashes?.candidate],
    ["evaluator", payload.evaluatorHash],
    ["benchmark snapshot", payload.benchmarkSnapshotHash],
    ["tool manifest", payload.toolManifestHash],
    ["event set", payload.eventHash],
    ["evidence set", payload.evidenceHash],
    ["metrics", payload.metricsHash],
  ];
  for (const [label, value] of hashes) {
    if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
      reasons.push(`Integrity ${label} hash is invalid.`);
    }
  }
  if (payload.executionEnvironment?.kind === "local_bwrap") {
    if (
      payload.containerImageDigest !== "not_applicable:local_bwrap"
      || !/^[a-f0-9]{64}$/u.test(
        payload.executionEnvironment.identityHash,
      )
    ) {
      reasons.push("Integrity local-bwrap execution identity is invalid.");
    }
  } else if (
    typeof payload.containerImageDigest !== "string"
    || !/^sha256:[a-f0-9]{64}$/u.test(payload.containerImageDigest)
  ) {
    reasons.push("Integrity container image digest is invalid.");
  }
  const validateIds = (label: string, values: readonly string[], requireOne: boolean): void => {
    if (!Array.isArray(values) || (requireOne && values.length === 0)) {
      reasons.push(`Integrity ${label} must contain ${requireOne ? "at least one " : "only "}stable ID.`);
      return;
    }
    if (values.some((value) => typeof value !== "string" || value.trim().length === 0)) {
      reasons.push(`Integrity ${label} contains an empty ID.`);
    }
    if (new Set(values).size !== values.length) reasons.push(`Integrity ${label} contains duplicate IDs.`);
  };
  validateIds("context packs", payload.contextPackIds, true);
  validateIds("random seeds", payload.randomSeeds, true);
  validateIds("provider exposure receipts", payload.exposureReceiptIds, payload.providerModel !== null);
  const expectedResult = payload.evaluationAction?.endsWith("_pass") ? "pass" : "fail";
  if (
    ![
      "development",
      "validation",
      "hidden_holdout",
      "shadow",
      "canary",
    ].includes(payload.evaluationStage)
  ) {
    reasons.push("Integrity evaluation stage is invalid.");
  }
  if (
    ![
      "development_pass",
      "development_fail",
      "validation_pass",
      "validation_fail",
      "hidden_holdout_pass",
      "hidden_holdout_fail",
      "shadow_pass",
      "shadow_fail",
      "canary_pass",
      "canary_fail",
    ].includes(payload.evaluationAction)
    || !payload.evaluationAction?.startsWith(`${payload.evaluationStage}_`)
  ) {
    reasons.push("Integrity evaluation action is not bound to its stage.");
  }
  if (payload.evaluationResult !== expectedResult) {
    reasons.push("Integrity evaluation result is not bound to its action.");
  }
  if (
    typeof payload.evaluationAttemptId !== "string"
    || payload.evaluationAttemptId.trim().length === 0
    || payload.evaluationAttemptId.length > 240
  ) {
    reasons.push("Integrity evaluation attempt ID is invalid.");
  }
  const hardGateFailures = Array.isArray(payload.hardGateFailures)
    ? payload.hardGateFailures
    : [];
  if (!Array.isArray(payload.hardGateFailures)) {
    reasons.push("Integrity hard-gate failures are malformed.");
  }
  validateIds(
    "hard-gate failures",
    hardGateFailures,
    false,
  );
  if (payload.evaluationResult === "pass" && hardGateFailures.length > 0) {
    reasons.push("A passing integrity result cannot contain hard-gate failures.");
  }
  if (payload.providerModel !== null) {
    if (
      typeof payload.providerModel?.providerId !== "string" ||
      typeof payload.providerModel?.modelId !== "string" ||
      payload.providerModel.providerId.trim().length === 0 ||
      payload.providerModel.modelId.trim().length === 0
    ) {
      reasons.push("Integrity provider/model binding is incomplete.");
    }
    if (
      typeof payload.providerModel?.promptTemplateHash !== "string" ||
      !/^[a-f0-9]{64}$/u.test(payload.providerModel.promptTemplateHash)
    ) {
      reasons.push("Integrity prompt-template hash is invalid.");
    }
  }
  if (!Number.isFinite(Date.parse(payload.signedAt))) reasons.push("Integrity signature timestamp is invalid.");
  return reasons;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return canonicalJson(left as unknown as JsonValue) === canonicalJson(right as unknown as JsonValue);
}

export class IntegrityAuthority {
  readonly #key: Uint8Array;

  constructor(localEvaluatorHmacKey: string | Uint8Array) {
    const bytes = typeof localEvaluatorHmacKey === "string"
      ? Buffer.from(localEvaluatorHmacKey, "utf8")
      : Buffer.from(localEvaluatorHmacKey);
    if (bytes.byteLength < 32) {
      throw new Error("The local evaluator HMAC key must contain at least 32 bytes.");
    }
    this.#key = new Uint8Array(bytes);
  }

  #signature(payload: ExperimentIntegrityPayload): string {
    return createHmac("sha256", this.#key)
      .update(canonicalJson(payload as unknown as JsonValue))
      .digest("hex");
  }

  createReceipt(payload: ExperimentIntegrityPayload): ExperimentIntegrityReceipt {
    const reasons = payloadValidationReasons(payload);
    if (reasons.length > 0) throw new Error(`Integrity receipt rejected: ${reasons.join("; ")}`);
    const signature = this.#signature(payload);
    const id = `integrity_${sha256(`${canonicalJson(payload as unknown as JsonValue)}:${signature}`).slice(0, 24)}`;
    return deepFreeze({ ...structuredClone(payload), id, algorithm: "hmac-sha256", signature });
  }

  verifyReceipt(
    receipt: ExperimentIntegrityReceipt,
    expected: ExpectedIntegrityBindings = {},
  ): IntegrityVerification {
    const reasons: string[] = [];
    if (receipt.algorithm !== "hmac-sha256") reasons.push("Integrity algorithm is not supported.");
    const payload = payloadFromReceipt(receipt);
    reasons.push(...payloadValidationReasons(payload));
    let expectedSignature = "";
    try {
      expectedSignature = this.#signature(payload);
      if (!safeEqualHex(receipt.signature, expectedSignature)) reasons.push("Integrity signature does not match payload.");
      const expectedId = `integrity_${sha256(`${canonicalJson(payload as unknown as JsonValue)}:${expectedSignature}`).slice(0, 24)}`;
      if (receipt.id !== expectedId) reasons.push("Integrity receipt ID does not match its signed payload.");
    } catch {
      reasons.push("Integrity payload is not canonicalizable.");
    }
    if (expected.experimentId !== undefined && receipt.experimentId !== expected.experimentId) {
      reasons.push("Experiment binding does not match.");
    }
    if (expected.charterHash !== undefined && receipt.charterHash !== expected.charterHash) {
      reasons.push("Charter binding does not match.");
    }
    if (expected.evaluatorHash !== undefined && receipt.evaluatorHash !== expected.evaluatorHash) {
      reasons.push("Evaluator binding does not match.");
    }
    if (
      expected.benchmarkSnapshotHash !== undefined &&
      receipt.benchmarkSnapshotHash !== expected.benchmarkSnapshotHash
    ) {
      reasons.push("Benchmark snapshot binding does not match.");
    }
    if (
      expected.baselineStrategyHash !== undefined &&
      receipt.strategyHashes.baseline !== expected.baselineStrategyHash
    ) {
      reasons.push("Baseline strategy binding does not match.");
    }
    if (
      expected.candidateStrategyHash !== undefined &&
      receipt.strategyHashes.candidate !== expected.candidateStrategyHash
    ) {
      reasons.push("Candidate strategy binding does not match.");
    }
    if (expected.evaluatorVersion !== undefined && receipt.evaluatorVersion !== expected.evaluatorVersion) {
      reasons.push("Evaluator version binding does not match.");
    }
    if (expected.containerImageDigest !== undefined && receipt.containerImageDigest !== expected.containerImageDigest) {
      reasons.push("Container image binding does not match.");
    }
    if (
      expected.executionEnvironmentKind !== undefined
      && receipt.executionEnvironment?.kind
        !== expected.executionEnvironmentKind
    ) reasons.push("Execution-environment kind does not match.");
    if (
      expected.executionEnvironmentIdentityHash !== undefined
      && receipt.executionEnvironment?.identityHash
        !== expected.executionEnvironmentIdentityHash
    ) reasons.push("Execution-environment identity does not match.");
    if (expected.toolManifestHash !== undefined && receipt.toolManifestHash !== expected.toolManifestHash) {
      reasons.push("Tool manifest binding does not match.");
    }
    const actualProviderId = receipt.providerModel?.providerId ?? null;
    const actualModelId = receipt.providerModel?.modelId ?? null;
    const actualPromptHash = receipt.providerModel?.promptTemplateHash ?? null;
    if (expected.providerId !== undefined && actualProviderId !== expected.providerId) {
      reasons.push("Provider binding does not match.");
    }
    if (expected.modelId !== undefined && actualModelId !== expected.modelId) {
      reasons.push("Model binding does not match.");
    }
    if (expected.promptTemplateHash !== undefined && actualPromptHash !== expected.promptTemplateHash) {
      reasons.push("Prompt-template binding does not match.");
    }
    if (expected.contextPackIds !== undefined && !sameStrings(receipt.contextPackIds, expected.contextPackIds)) {
      reasons.push("Context-pack bindings do not match.");
    }
    if (expected.randomSeeds !== undefined && !sameStrings(receipt.randomSeeds, expected.randomSeeds)) {
      reasons.push("Random-seed bindings do not match.");
    }
    if (expected.eventHash !== undefined && receipt.eventHash !== expected.eventHash) {
      reasons.push("Event-set binding does not match.");
    }
    if (expected.evidenceHash !== undefined && receipt.evidenceHash !== expected.evidenceHash) {
      reasons.push("Evidence-set binding does not match.");
    }
    if (expected.metricsHash !== undefined && receipt.metricsHash !== expected.metricsHash) {
      reasons.push("Metrics binding does not match.");
    }
    if (
      expected.exposureReceiptIds !== undefined &&
      !sameStrings(receipt.exposureReceiptIds, expected.exposureReceiptIds)
    ) {
      reasons.push("Provider-exposure receipt bindings do not match.");
    }
    if (
      expected.evaluationStage !== undefined
      && receipt.evaluationStage !== expected.evaluationStage
    ) reasons.push("Evaluation-stage binding does not match.");
    if (
      expected.evaluationAction !== undefined
      && receipt.evaluationAction !== expected.evaluationAction
    ) reasons.push("Evaluation-action binding does not match.");
    if (
      expected.evaluationResult !== undefined
      && receipt.evaluationResult !== expected.evaluationResult
    ) reasons.push("Evaluation-result binding does not match.");
    if (
      expected.evaluationAttemptId !== undefined
      && receipt.evaluationAttemptId !== expected.evaluationAttemptId
    ) reasons.push("Evaluation-attempt binding does not match.");
    if (
      expected.hardGateFailures !== undefined
      && !sameStrings(receipt.hardGateFailures, expected.hardGateFailures)
    ) reasons.push("Hard-gate failure bindings do not match.");
    return { valid: reasons.length === 0, reasons };
  }

  assertReceipt(
    receipt: ExperimentIntegrityReceipt,
    expected: ExpectedIntegrityBindings = {},
  ): ExperimentIntegrityReceipt {
    const verification = this.verifyReceipt(receipt, expected);
    if (!verification.valid) throw new Error(`Integrity verification failed: ${verification.reasons.join("; ")}`);
    return receipt;
  }
}

/**
 * Content-free local round trip used only for readiness. It proves that the
 * configured authority can sign and verify the complete current receipt
 * schema; it does not claim that a lab or worker is ready.
 */
export function attestIntegrityAuthority(
  authority: IntegrityAuthority | undefined,
): boolean {
  if (!authority) return false;
  const hash = "0".repeat(64);
  try {
    const receipt = authority.createReceipt({
      experimentId: "readiness-self-test",
      charterHash: hash,
      strategyHashes: { baseline: hash, candidate: hash },
      evaluatorVersion: "readiness-self-test",
      evaluatorHash: hash,
      benchmarkSnapshotHash: hash,
      containerImageDigest: `sha256:${hash}`,
      toolManifestHash: hash,
      providerModel: null,
      contextPackIds: ["readiness-context"],
      randomSeeds: ["readiness-seed"],
      eventHash: hash,
      evidenceHash: hash,
      metricsHash: hash,
      exposureReceiptIds: [],
      evaluationStage: "development",
      evaluationAction: "development_pass",
      evaluationResult: "pass",
      evaluationAttemptId: "readiness-attempt",
      hardGateFailures: [],
      signedAt: "2000-01-01T00:00:00.000Z",
    });
    return authority.verifyReceipt(receipt, {
      experimentId: "readiness-self-test",
      evaluationStage: "development",
      evaluationAction: "development_pass",
      evaluationResult: "pass",
      evaluationAttemptId: "readiness-attempt",
      hardGateFailures: [],
    }).valid;
  } catch {
    return false;
  }
}
