import { describe, expect, test } from "bun:test";
import {
  IntegrityAuthority,
  ResearchReadinessReceiptAuthority,
  ResearchReadinessAttestor,
  type ResearchDependencyAttestation,
} from "../../../server/research";

const NOW = "2026-07-24T12:00:00.000Z";
const HASH = "a".repeat(64);
const receiptAuthority = new ResearchReadinessReceiptAuthority(
  "research-readiness-receipt-key-material-32-bytes",
);

function attestation(
  dependency: ResearchDependencyAttestation["dependency"],
  overrides: Partial<ResearchDependencyAttestation> = {},
): ResearchDependencyAttestation {
  const base = {
    schemaVersion: "2.4" as const,
    dependency,
    attestorId: `independent-${dependency}-attestor`,
    status: "pass" as const,
    observedAt: "2026-07-24T11:59:00.000Z",
    expiresAt: "2026-07-24T12:04:00.000Z",
    evidenceHash: HASH,
    probeIdentity: {
      evaluatorId: "ti-scale.readiness-test",
      evaluatorSha256: HASH,
      isolationToolId: "bubblewrap-test",
      isolationToolSha256: HASH,
      resourceLimitToolSha256: HASH,
      evaluatorToolSha256: HASH,
    },
    resourceLimits: {
      addressSpaceBytes: 134_217_728,
      cpuSeconds: 2,
      maxProcesses: 16,
      maxFileBytes: 1_048_576,
      maxOpenFiles: 64,
    },
    failureCode: null,
    controls: {
      resetVerified: dependency === "disposable_lab",
      liveClientTargetsAllowed: false,
      productionSecretsMounted: false,
      productionMutationAllowed: false,
      quotaBound: true,
    },
  };
  const {
    receiptId: _receiptId,
    algorithm: _algorithm,
    signature: _signature,
    ...unsignedOverrides
  } = overrides;
  return receiptAuthority.createReceipt({
    ...base,
    ...unsignedOverrides,
  });
}

describe("ResearchReadinessAttestor", () => {
  test("requires fresh independently verified receipts and a real signing round trip", () => {
    const lab = attestation("disposable_lab");
    const worker = attestation("isolated_worker");
    const readiness = new ResearchReadinessAttestor({
      integrityAuthority: new IntegrityAuthority(
        "research-readiness-signing-key-material-32-bytes",
      ),
      readDisposableLabAttestation: () => lab,
      verifyDisposableLabAttestation: (candidate) =>
        receiptAuthority.verifyReceipt(candidate),
      readIsolatedWorkerAttestation: () => worker,
      verifyIsolatedWorkerAttestation: (candidate) =>
        receiptAuthority.verifyReceipt(candidate),
      clock: () => new Date(NOW),
    }).snapshot();
    expect(readiness).toEqual({
      disposableLabReady: true,
      isolatedWorkerReady: true,
      integritySigningKeyReady: true,
    });
  });

  test("does not substitute configuration presence for missing or rejected attestations", () => {
    const readiness = new ResearchReadinessAttestor({
      integrityAuthority: new IntegrityAuthority(
        "research-readiness-signing-key-material-32-bytes",
      ),
      readDisposableLabAttestation: () => undefined,
      verifyDisposableLabAttestation: () => true,
      readIsolatedWorkerAttestation: () => attestation("isolated_worker"),
      verifyIsolatedWorkerAttestation: () => false,
      clock: () => new Date(NOW),
    }).snapshot();
    expect(readiness).toEqual({
      disposableLabReady: false,
      isolatedWorkerReady: false,
      integritySigningKeyReady: true,
    });
  });

  test("rejects stale, unsafe, wrong-kind, and malformed receipts", () => {
    const invalidLabReceipts = [
      attestation("disposable_lab", {
        expiresAt: "2026-07-24T11:59:59.000Z",
      }),
      attestation("disposable_lab", {
        controls: {
          ...attestation("disposable_lab").controls,
          liveClientTargetsAllowed: true,
        },
      }),
      attestation("isolated_worker"),
      attestation("disposable_lab", { evidenceHash: "not-a-hash" }),
    ] as const;
    for (const invalidLab of invalidLabReceipts) {
      const readiness = new ResearchReadinessAttestor({
        readDisposableLabAttestation: () => invalidLab,
        verifyDisposableLabAttestation: () => true,
        readIsolatedWorkerAttestation: () => undefined,
        verifyIsolatedWorkerAttestation: () => true,
        clock: () => new Date(NOW),
      }).snapshot();
      expect(readiness.disposableLabReady).toBe(false);
      expect(readiness.integritySigningKeyReady).toBe(false);
    }
  });
});
