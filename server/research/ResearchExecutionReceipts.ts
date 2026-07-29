import {
  createHash,
  createHmac,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { canonicalJson, deepFreeze, type JsonValue } from "./canonical";

const HASH = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,240}$/u;
const MAXIMUM_RECEIPT_AGE_MS = 5 * 60_000;

export type ResearchExecutionReceiptKind = "lab" | "worker";

export interface ResearchExecutionBindings {
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly benchmarkSnapshotHash: string;
  readonly evaluatorHash: string;
  readonly toolManifestHash: string;
  readonly resetGeneration: string;
}

export interface ResearchResourceLimits {
  readonly addressSpaceBytes: number;
  readonly cpuSeconds: number;
  readonly maxProcesses: number;
  readonly maxFileBytes: number;
  readonly maxOpenFiles: number;
}

export interface LabReceiptSubject {
  readonly environmentDigest: string;
  readonly baselineStateHash: string;
  readonly dirtyStateHash: string;
  readonly resetStateHash: string;
  readonly workspacePathHash: string;
  readonly resetMode: "recreate";
  readonly ownerUid: number;
  readonly ownerGid: number;
}

export interface WorkerReceiptSubject {
  /** Host PID tracked by the trusted launcher. */
  readonly processId: number;
  /** PID observed by the same worker inside its private PID namespace. */
  readonly namespaceProcessId: number;
  readonly processStartTicks: string;
  readonly userId: number;
  readonly groupId: number;
  readonly namespaceIds: Readonly<{
    readonly mount: string;
    readonly network: string;
    readonly pid: string;
    readonly user: string;
  }>;
  readonly parentNamespaceIds: Readonly<{
    readonly mount: string;
    readonly network: string;
    readonly pid: string;
    readonly user: string;
  }>;
  readonly noNewPrivileges: true;
  readonly effectiveCapabilities: "0000000000000000";
  readonly permittedCapabilities: "0000000000000000";
  readonly ambientCapabilities: "0000000000000000";
  readonly fixtureReadOnly: true;
  readonly workFilesystemPrivate: true;
  readonly networkNamespaceIsolated: true;
  readonly networkConnectDenied: true;
  readonly credentialEnvironmentEmpty: true;
  readonly mountPolicyHash: string;
  readonly workerSourceSha256: string;
  readonly launcherIdentityHash: string;
  readonly labStateHash: string;
  readonly resourceLimits: ResearchResourceLimits;
  readonly orphanControl: "pid_namespace_and_process_group";
}

export interface UnsignedResearchExecutionReceipt<
  TKind extends ResearchExecutionReceiptKind = ResearchExecutionReceiptKind,
> extends ResearchExecutionBindings {
  readonly schemaVersion: "ti-scale.research-execution-receipt.v1";
  readonly kind: TKind;
  readonly bootId: string;
  readonly keyId: string;
  readonly challengeHash: string;
  readonly subjectIdentityHash: string;
  readonly evidenceHash: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly controls: {
    readonly liveClientTargetsAllowed: false;
    readonly productionSecretsMounted: false;
    readonly productionMutationAllowed: false;
    readonly publicProviderExecutionAllowed: false;
    readonly quotaBound: true;
    readonly resetVerified: boolean;
  };
  readonly subject: TKind extends "lab"
    ? LabReceiptSubject
    : WorkerReceiptSubject;
}

export interface ResearchExecutionReceipt<
  TKind extends ResearchExecutionReceiptKind = ResearchExecutionReceiptKind,
> extends UnsignedResearchExecutionReceipt<TKind> {
  readonly receiptId: string;
  readonly algorithm: "hmac-sha256";
  readonly signature: string;
}

export interface ResearchReceiptVerification {
  readonly valid: boolean;
  readonly reasons: readonly string[];
}

function hash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function safeEqualHex(left: string, right: string): boolean {
  if (!HASH.test(left) || !HASH.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function validInstant(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function validateBindings(
  receipt: UnsignedResearchExecutionReceipt,
  reasons: string[],
): void {
  for (const [label, value] of [
    ["experiment", receipt.experimentId],
    ["scenario", receipt.scenarioId],
    ["boot", receipt.bootId],
  ] as const) {
    if (!SAFE_ID.test(value)) reasons.push(`${label}_identity_invalid`);
  }
  for (const [label, value] of [
    ["benchmark", receipt.benchmarkSnapshotHash],
    ["evaluator", receipt.evaluatorHash],
    ["tool_manifest", receipt.toolManifestHash],
    ["reset_generation", receipt.resetGeneration],
    ["challenge", receipt.challengeHash],
    ["subject", receipt.subjectIdentityHash],
    ["evidence", receipt.evidenceHash],
  ] as const) {
    if (!HASH.test(value)) reasons.push(`${label}_hash_invalid`);
  }
}

function exactBindings(
  receipt: UnsignedResearchExecutionReceipt,
  expected: ResearchExecutionBindings,
  reasons: string[],
): void {
  for (const [label, actual, wanted] of [
    ["experiment", receipt.experimentId, expected.experimentId],
    ["scenario", receipt.scenarioId, expected.scenarioId],
    ["benchmark", receipt.benchmarkSnapshotHash, expected.benchmarkSnapshotHash],
    ["evaluator", receipt.evaluatorHash, expected.evaluatorHash],
    ["tool_manifest", receipt.toolManifestHash, expected.toolManifestHash],
    ["reset_generation", receipt.resetGeneration, expected.resetGeneration],
  ] as const) {
    if (actual !== wanted) reasons.push(`${label}_binding_mismatch`);
  }
}

/**
 * One process boot owns three independently derived keys. The public model,
 * experiment worker, and disposable fixture receive none of them.
 */
export class ResearchExecutionReceiptKeyring {
  readonly bootId: string;
  readonly #clock: () => Date;
  readonly #ttlMs: number;
  readonly #labKey: Uint8Array;
  readonly #workerKey: Uint8Array;
  readonly #admissionKey: Uint8Array;
  readonly #keyIds: Readonly<Record<ResearchExecutionReceiptKind, string>>;

  constructor(
    masterKey: string | Uint8Array,
    options: {
      readonly bootId?: string;
      readonly clock?: () => Date;
      readonly receiptTtlMs?: number;
    } = {},
  ) {
    const bytes = typeof masterKey === "string"
      ? Buffer.from(masterKey, "utf8")
      : Buffer.from(masterKey);
    if (bytes.byteLength < 32) {
      throw new Error("Research execution master key must contain at least 32 bytes.");
    }
    this.bootId = options.bootId ?? `research-boot-${randomUUID()}`;
    if (!SAFE_ID.test(this.bootId)) {
      throw new Error("Research execution boot ID is invalid.");
    }
    this.#clock = options.clock ?? (() => new Date());
    this.#ttlMs = options.receiptTtlMs ?? 60_000;
    if (
      !Number.isSafeInteger(this.#ttlMs)
      || this.#ttlMs < 1_000
      || this.#ttlMs > MAXIMUM_RECEIPT_AGE_MS
    ) {
      throw new Error("Research execution receipt TTL must be between one second and five minutes.");
    }
    const derive = (domain: string): Uint8Array =>
      new Uint8Array(
        createHmac("sha256", bytes)
          .update(`ti-scale/research-execution/${domain}/v1`, "utf8")
          .digest(),
      );
    this.#labKey = derive("lab-receipt");
    this.#workerKey = derive("worker-receipt");
    this.#admissionKey = derive("admission");
    this.#keyIds = Object.freeze({
      lab: hash(Buffer.from(this.#labKey).toString("hex")),
      worker: hash(Buffer.from(this.#workerKey).toString("hex")),
    });
  }

  private key(kind: ResearchExecutionReceiptKind): Uint8Array {
    return kind === "lab" ? this.#labKey : this.#workerKey;
  }

  private signature(
    kind: ResearchExecutionReceiptKind,
    payload: UnsignedResearchExecutionReceipt,
  ): string {
    return createHmac("sha256", this.key(kind))
      .update(`ti-scale.research-execution.${kind}.v1\0`, "utf8")
      .update(canonicalJson(payload as unknown as JsonValue), "utf8")
      .digest("hex");
  }

  create<TKind extends ResearchExecutionReceiptKind>(
    kind: TKind,
    input: Omit<
      UnsignedResearchExecutionReceipt<TKind>,
      "bootId" | "issuedAt" | "expiresAt" | "keyId" | "kind" | "schemaVersion"
    >,
  ): ResearchExecutionReceipt<TKind> {
    const issuedAt = this.#clock();
    const payload = {
      schemaVersion: "ti-scale.research-execution-receipt.v1" as const,
      kind,
      bootId: this.bootId,
      keyId: this.#keyIds[kind],
      ...structuredClone(input),
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + this.#ttlMs).toISOString(),
    } as UnsignedResearchExecutionReceipt<TKind>;
    const reasons: string[] = [];
    validateBindings(payload, reasons);
    if (
      payload.controls.liveClientTargetsAllowed
      || payload.controls.productionSecretsMounted
      || payload.controls.productionMutationAllowed
      || payload.controls.publicProviderExecutionAllowed
      || !payload.controls.quotaBound
      || (kind === "lab" && !payload.controls.resetVerified)
    ) {
      reasons.push("unsafe_controls");
    }
    if (reasons.length > 0) {
      throw new Error(`Research execution receipt rejected: ${reasons.join(",")}`);
    }
    const signature = this.signature(kind, payload);
    const receiptId = `research_${kind}_${hash(
      `${canonicalJson(payload as unknown as JsonValue)}:${signature}`,
    ).slice(0, 24)}`;
    return deepFreeze({
      ...payload,
      receiptId,
      algorithm: "hmac-sha256" as const,
      signature,
    }) as ResearchExecutionReceipt<TKind>;
  }

  verify<TKind extends ResearchExecutionReceiptKind>(
    receipt: ResearchExecutionReceipt<TKind>,
    expected: ResearchExecutionBindings & {
      readonly kind: TKind;
      readonly challengeHash?: string;
      readonly subjectIdentityHash?: string;
    },
  ): ResearchReceiptVerification {
    const reasons: string[] = [];
    if (
      receipt.schemaVersion !== "ti-scale.research-execution-receipt.v1"
      || receipt.kind !== expected.kind
      || receipt.algorithm !== "hmac-sha256"
      || receipt.bootId !== this.bootId
      || receipt.keyId !== this.#keyIds[expected.kind]
    ) {
      reasons.push("issuer_or_kind_mismatch");
    }
    validateBindings(receipt, reasons);
    exactBindings(receipt, expected, reasons);
    if (
      expected.challengeHash
      && receipt.challengeHash !== expected.challengeHash
    ) reasons.push("challenge_binding_mismatch");
    if (
      expected.subjectIdentityHash
      && receipt.subjectIdentityHash !== expected.subjectIdentityHash
    ) reasons.push("subject_binding_mismatch");
    if (
      receipt.controls.liveClientTargetsAllowed
      || receipt.controls.productionSecretsMounted
      || receipt.controls.productionMutationAllowed
      || receipt.controls.publicProviderExecutionAllowed
      || !receipt.controls.quotaBound
      || (receipt.kind === "lab" && !receipt.controls.resetVerified)
    ) reasons.push("unsafe_controls");
    const issuedAt = Date.parse(receipt.issuedAt);
    const expiresAt = Date.parse(receipt.expiresAt);
    const now = this.#clock().getTime();
    if (
      !validInstant(receipt.issuedAt)
      || !validInstant(receipt.expiresAt)
      || issuedAt > now
      || expiresAt <= now
      || expiresAt <= issuedAt
      || now - issuedAt > MAXIMUM_RECEIPT_AGE_MS
    ) reasons.push("stale_or_future_receipt");
    const { receiptId, algorithm: _algorithm, signature, ...payload } = receipt;
    const expectedSignature = this.signature(
      receipt.kind,
      payload as UnsignedResearchExecutionReceipt,
    );
    const expectedId = `research_${receipt.kind}_${hash(
      `${canonicalJson(payload as unknown as JsonValue)}:${expectedSignature}`,
    ).slice(0, 24)}`;
    if (
      receiptId !== expectedId
      || !safeEqualHex(signature, expectedSignature)
    ) reasons.push("signature_mismatch");
    return deepFreeze({
      valid: reasons.length === 0,
      reasons: [...new Set(reasons)],
    });
  }

  createAdmissionSignature(payload: JsonValue): string {
    return createHmac("sha256", this.#admissionKey)
      .update("ti-scale.research-execution.admission.v1\0", "utf8")
      .update(canonicalJson(payload), "utf8")
      .digest("hex");
  }

  verifyAdmissionSignature(payload: JsonValue, signature: string): boolean {
    return safeEqualHex(signature, this.createAdmissionSignature(payload));
  }
}
