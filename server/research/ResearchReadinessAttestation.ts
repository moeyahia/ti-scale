import type { IntegrityAuthority } from "./IntegrityVerifier";
import { attestIntegrityAuthority } from "./IntegrityVerifier";
import type { ResearchRuntimeReadiness } from "./ResearchLabRepository";

export type ResearchDependencyKind = "disposable_lab" | "isolated_worker";

export interface ResearchDependencyAttestation {
  readonly schemaVersion: "2.4";
  readonly receiptId: string;
  readonly algorithm: "hmac-sha256";
  readonly signature: string;
  readonly dependency: ResearchDependencyKind;
  readonly attestorId: string;
  readonly status: "pass" | "fail";
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly evidenceHash: string;
  readonly probeIdentity: {
    readonly evaluatorId: string;
    readonly evaluatorSha256: string;
    readonly isolationToolId: string;
    readonly isolationToolSha256: string;
    readonly resourceLimitToolSha256: string;
    readonly evaluatorToolSha256: string;
  };
  readonly resourceLimits: {
    readonly addressSpaceBytes: number;
    readonly cpuSeconds: number;
    readonly maxProcesses: number;
    readonly maxFileBytes: number;
    readonly maxOpenFiles: number;
  };
  readonly failureCode: string | null;
  readonly controls: {
    readonly resetVerified: boolean;
    readonly liveClientTargetsAllowed: boolean;
    readonly productionSecretsMounted: boolean;
    readonly productionMutationAllowed: boolean;
    readonly quotaBound: boolean;
  };
}

export interface ResearchReadinessAttestorOptions {
  readonly integrityAuthority?: IntegrityAuthority;
  readonly readDisposableLabAttestation: (
  ) => ResearchDependencyAttestation | undefined;
  readonly verifyDisposableLabAttestation: (
    attestation: ResearchDependencyAttestation,
  ) => boolean;
  readonly readIsolatedWorkerAttestation: (
  ) => ResearchDependencyAttestation | undefined;
  readonly verifyIsolatedWorkerAttestation: (
    attestation: ResearchDependencyAttestation,
  ) => boolean;
  readonly clock?: () => Date;
  readonly maximumAttestationAgeMs?: number;
}

function validText(value: unknown, maximum = 240): value is string {
  return typeof value === "string"
    && value.trim().length > 0
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validInstant(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validControls(
  dependency: ResearchDependencyKind,
  controls: ResearchDependencyAttestation["controls"],
): boolean {
  if (
    !controls
    || Object.values(controls).some((value) => typeof value !== "boolean")
    || controls.liveClientTargetsAllowed
    || controls.productionSecretsMounted
    || controls.productionMutationAllowed
    || !controls.quotaBound
  ) return false;
  return dependency === "disposable_lab"
    ? controls.resetVerified
    : true;
}

function validAttestation(
  attestation: ResearchDependencyAttestation | undefined,
  expectedDependency: ResearchDependencyKind,
  verify: (attestation: ResearchDependencyAttestation) => boolean,
  now: number,
  maximumAgeMs: number,
): boolean {
  if (
    !attestation
    || attestation.schemaVersion !== "2.4"
    || attestation.dependency !== expectedDependency
    || attestation.status !== "pass"
    || attestation.algorithm !== "hmac-sha256"
    || !/^[a-f0-9]{64}$/u.test(attestation.signature)
    || !validText(attestation.receiptId)
    || !validText(attestation.attestorId)
    || !/^[a-f0-9]{64}$/u.test(attestation.evidenceHash)
    || !validText(attestation.probeIdentity?.evaluatorId)
    || !validText(attestation.probeIdentity?.isolationToolId)
    || !/^[a-f0-9]{64}$/u.test(
      attestation.probeIdentity?.evaluatorSha256 ?? "",
    )
    || !/^[a-f0-9]{64}$/u.test(
      attestation.probeIdentity?.isolationToolSha256 ?? "",
    )
    || !/^[a-f0-9]{64}$/u.test(
      attestation.probeIdentity?.resourceLimitToolSha256 ?? "",
    )
    || !/^[a-f0-9]{64}$/u.test(
      attestation.probeIdentity?.evaluatorToolSha256 ?? "",
    )
    || attestation.failureCode !== null
    || !Number.isSafeInteger(
      attestation.resourceLimits?.addressSpaceBytes,
    )
    || !Number.isSafeInteger(attestation.resourceLimits?.cpuSeconds)
    || !Number.isSafeInteger(attestation.resourceLimits?.maxProcesses)
    || !Number.isSafeInteger(attestation.resourceLimits?.maxFileBytes)
    || !Number.isSafeInteger(attestation.resourceLimits?.maxOpenFiles)
    || !validInstant(attestation.observedAt)
    || !validInstant(attestation.expiresAt)
    || !validControls(expectedDependency, attestation.controls)
  ) return false;
  const observedAt = Date.parse(attestation.observedAt);
  const expiresAt = Date.parse(attestation.expiresAt);
  if (
    observedAt > now
    || expiresAt <= now
    || expiresAt <= observedAt
    || now - observedAt > maximumAgeMs
  ) return false;
  try {
    return verify(attestation) === true;
  } catch {
    return false;
  }
}

/**
 * Produces the Research Lab readiness projection only from independently
 * verifiable, fresh receipts. Configuration or environment-variable presence
 * is deliberately insufficient.
 */
export class ResearchReadinessAttestor {
  readonly #clock: () => Date;
  readonly #maximumAttestationAgeMs: number;

  constructor(
    private readonly options: ResearchReadinessAttestorOptions,
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#maximumAttestationAgeMs =
      options.maximumAttestationAgeMs ?? 5 * 60_000;
    if (
      !Number.isSafeInteger(this.#maximumAttestationAgeMs)
      || this.#maximumAttestationAgeMs < 1_000
      || this.#maximumAttestationAgeMs > 60 * 60_000
    ) {
      throw new Error(
        "Research readiness attestation age must be between one second and one hour.",
      );
    }
  }

  snapshot(): ResearchRuntimeReadiness {
    const now = this.#clock().getTime();
    return Object.freeze({
      disposableLabReady: validAttestation(
        this.options.readDisposableLabAttestation(),
        "disposable_lab",
        this.options.verifyDisposableLabAttestation,
        now,
        this.#maximumAttestationAgeMs,
      ),
      isolatedWorkerReady: validAttestation(
        this.options.readIsolatedWorkerAttestation(),
        "isolated_worker",
        this.options.verifyIsolatedWorkerAttestation,
        now,
        this.#maximumAttestationAgeMs,
      ),
      integritySigningKeyReady: attestIntegrityAuthority(
        this.options.integrityAuthority,
      ),
    });
  }
}
