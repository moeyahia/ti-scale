import type {
  AttackKnowledgeCompilerInput,
  OperationalHazardKnowledge,
} from "../AttackKnowledgeCompiler";

/**
 * Sanitized, source-only reconciliation fixtures derived from a private,
 * authorized lab history. Operational locators remain outside this module.
 * These inputs are candidates for operator review; they are not verified
 * memory and must never be promoted automatically.
 */

const APPLICATION_SOURCE_HASH = "c6ba640817240dfff45bc42d3c4f5e7cfadf5348f3e9af45da6a1077005dc243";
const KERNEL_V2_SOURCE_HASH = "166c7171e1b9bda8d3d2a713572f50698a70161fbc81816f7328cdc02181d686";
const KERNEL_V5_SOURCE_HASH = "4aab21054f12b80d5c8e778680128052880eaa1dfff8e8d77dfb0285955c694d";

const OPERATOR_REPORTED_RESET_MINIMUM = 11;

const applicationLayoutDumpHang: OperationalHazardKnowledge = {
  kind: "operational_hazard",
  product: {
    name: "Microsoft Internet Information Services",
    exactVersion: "10.0",
  },
  stack: [
    { nodeType: "framework", name: "ASP.NET", exactVersion: "4.0.30319" },
    { nodeType: "runtime", name: "V8 JavaScript engine", exactVersion: "12.2.0" },
    { nodeType: "operating_system", name: "Windows Server", exactVersion: "2022 build 20348.4171" },
  ],
  procedure: {
    name: "Three-object V8 layout dump using DebugPrint",
    version: "sha256:37bdc40ebe262063dc642c0c80bd421c67f56d4427564ca0481f14bc6c06586a",
    orderedSteps: [
      "Prove one harmless scalar expression completes",
      "Attempt four bounded large-buffer allocations and continue after allocation errors",
      "Create three small diagnostic objects",
      "Print internal layout details for all three objects within one request",
      "Stop at the request deadline and re-check the harmless scalar expression",
    ],
    normalizedParameters: {
      allocationAttempts: 4,
      allocationBytesEach: 2_145_386_496,
      debugPrintCalls: 3,
      requestTimeoutMs: 45_000,
      automaticRetries: 0,
      concurrency: 1,
    },
    prerequisites: [
      "The exact application and JavaScript-engine versions match",
      "Internal layout printing is enabled",
      "A harmless scalar expression has just completed",
    ],
  },
  hazard: {
    name: "Expression worker stops returning after the reviewed layout-dump procedure",
    observedSymptom: "The base page remains reachable while expression requests stop completing",
    affectedComponent: "Application expression worker and result watcher",
    stateBefore: "A harmless scalar expression completes in under ten seconds",
    stateAfter: "The layout request times out and the next harmless expression does not complete",
    unsafeRetryConditions: [
      "The harmless expression health check does not complete",
      "The prior layout request has no terminal outcome",
      "The application worker has not been recycled or restored",
    ],
    healthGate: [
      "Restore a clean application worker",
      "Confirm no earlier expression request remains in flight",
      "Run exactly one harmless scalar expression and require the expected result",
      "Do not authorize this exact known-bad layout-dump procedure version",
    ],
    recoveryActionSummary: "Restore a clean application worker and pass one harmless expression health check",
    recoveryCost: {
      exactProcedureResetCount: 1,
      operatorReportedResetCountMinimum: OPERATOR_REPORTED_RESET_MINIMUM,
      requiresDisposableTargetReset: true,
    },
    saferAlternative: {
      name: "Single-stage offline layout calibration",
      orderedSteps: [
        "Inspect the exact engine artifacts offline",
        "Choose one bounded non-printing calibration candidate",
        "Run one candidate only after a clean health gate",
        "Stop immediately on a timeout or missing terminal marker",
      ],
    },
    concurrencyMinimum: 1,
    timingWindowMs: 45_000,
  },
  corroboration: {
    exactProcedureAttemptCount: 1,
    exactProcedureReproducibilityCount: 1,
    exactProcedureEvidenceCount: 4,
  },
};

const kernelTransitionV2Hang: OperationalHazardKnowledge = {
  kind: "operational_hazard",
  product: {
    name: "VL-Reaper kernel driver",
    exactVersion: "sha256:f5bf94f7c1b46b448f315a5dbfcde819079db0d2074da3e5c0208d87f58e7052",
  },
  stack: [
    { nodeType: "operating_system", name: "Windows Server", exactVersion: "2022 build 20348.4171" },
    { nodeType: "kernel", name: "Windows ntoskrnl", exactVersion: "10.0.20348.4163" },
  ],
  procedure: {
    name: "Exact-image Path B kernel transition",
    version: "sha256:1d9452ba40b4b06e8fcca0973273d7f2be8363ca5b60e7b941675705f6b28dbc",
    orderedSteps: [
      "Verify the exact driver and kernel-image fingerprints",
      "Run the non-executing preflight and require every gate to pass",
      "Issue one reviewed Path B transition attempt",
      "Require an independent elevated-identity marker and a terminal return",
      "Stop without retry when either proof is absent",
    ],
    normalizedParameters: {
      automaticRetries: 0,
      maximumAttemptsPerBoot: 1,
      mode: "execute",
      procedurePath: "B",
      ropQwords: 11,
      userMetadataPteRoundTrip: true,
      requireIndependentIdentityProof: true,
    },
    prerequisites: [
      "The driver fingerprint matches exactly",
      "The kernel file version and fingerprint match exactly",
      "All boot-dependent values were freshly derived",
      "The non-executing preflight completed successfully",
    ],
  },
  hazard: {
    name: "Path B v2 blocks after the final chain entry without trusted elevation proof",
    observedSymptom: "The transition request does not return and its shell stops responding while network services remain available",
    affectedComponent: "Kernel transition request and issuing process",
    stateBefore: "A fresh low-privilege shell and all non-executing gates are healthy",
    stateAfter: "The issuing shell is blocked with no terminal marker or elevated-identity evidence",
    unsafeRetryConditions: [
      "The previous transition request has no terminal outcome",
      "The system has not returned to a verified clean boot",
      "The same procedure binary still contains the user-metadata round trip",
    ],
    healthGate: [
      "Restore and verify a clean boot",
      "Confirm the previous transition process is absent",
      "Recompute all boot-dependent values",
      "Do not authorize this exact known-bad procedure version",
    ],
    recoveryActionSummary: "Preserve the failure evidence and restore a verified clean boot before offline analysis",
    recoveryCost: {
      exactProcedureResetCount: 1,
      operatorReportedResetCountMinimum: OPERATOR_REPORTED_RESET_MINIMUM,
      requiresDisposableTargetReset: true,
    },
    saferAlternative: {
      name: "Offline exact-image control-flow review",
      orderedSteps: [
        "Compare the driver and kernel binaries with the procedure assumptions",
        "Remove the unsafe user-metadata dependency in a distinct procedure version",
        "Validate the distinct version without issuing the transition request",
      ],
    },
    concurrencyMinimum: 1,
    timingWindowMs: 180_000,
  },
  corroboration: {
    exactProcedureAttemptCount: 1,
    exactProcedureReproducibilityCount: 1,
    exactProcedureEvidenceCount: 5,
  },
};

const kernelTransitionV5Hang: OperationalHazardKnowledge = {
  kind: "operational_hazard",
  product: {
    name: "VL-Reaper kernel driver",
    exactVersion: "sha256:f5bf94f7c1b46b448f315a5dbfcde819079db0d2074da3e5c0208d87f58e7052",
  },
  stack: [
    { nodeType: "operating_system", name: "Windows Server", exactVersion: "2022 build 20348.4171" },
    { nodeType: "kernel", name: "Windows ntoskrnl", exactVersion: "10.0.20348.4163" },
  ],
  procedure: {
    name: "Exact-image Path B kernel transition",
    version: "sha256:07d6a27fdbfc206e083ebb3b296e3fdd0c3744bc6bd81944fa004357f4117430",
    orderedSteps: [
      "Verify the exact driver, kernel image, and current boot",
      "Run the non-executing preflight and exact eight-entry chain validator",
      "Issue one watcher-backed Path B transition attempt",
      "Require independent elevated-identity, restoration, and terminal-return markers",
      "Stop without retry when any required marker is absent",
    ],
    normalizedParameters: {
      automaticRetries: 0,
      maximumAttemptsPerBoot: 1,
      mode: "execute",
      procedurePath: "B",
      ropQwords: 8,
      returnRegisterAssumption: "best_effort",
      watcherRequired: true,
      requireIndependentIdentityProof: true,
    },
    prerequisites: [
      "The driver fingerprint matches exactly",
      "The kernel file version and fingerprint match exactly",
      "The boot identity has not changed since preflight",
      "Every non-executing gate and chain validator completed successfully",
    ],
  },
  hazard: {
    name: "Path B v5 blocks after transition begins without watcher or return proof",
    observedSymptom: "The transition begins but emits no trusted identity, restoration, or terminal-return marker for more than five minutes",
    affectedComponent: "Kernel transition return path and issuing process",
    stateBefore: "A fresh low-privilege shell and all non-executing gates are healthy",
    stateAfter: "The issuing shell is blocked while ordinary network services remain responsive",
    unsafeRetryConditions: [
      "The previous transition request has no terminal outcome",
      "The system has not returned to a verified clean boot",
      "The return-register assumption is still only best effort",
    ],
    healthGate: [
      "Restore and verify a clean boot",
      "Confirm the previous transition process is absent",
      "Recompute all boot-dependent values",
      "Do not authorize this exact known-bad procedure version",
    ],
    recoveryActionSummary: "Preserve the failure evidence and restore a verified clean boot before any distinct diagnostic",
    recoveryCost: {
      operatorReportedResetCountMinimum: OPERATOR_REPORTED_RESET_MINIMUM,
      requiresDisposableTargetReset: true,
    },
    saferAlternative: {
      name: "Non-executing return-path diagnostic",
      orderedSteps: [
        "Inspect the exact transition and return path offline",
        "Replace the best-effort return assumption in a distinct procedure version",
        "Validate that distinct version with non-executing gates first",
      ],
    },
    concurrencyMinimum: 1,
    timingWindowMs: 310_000,
  },
  corroboration: {
    exactProcedureAttemptCount: 1,
    exactProcedureReproducibilityCount: 1,
    exactProcedureEvidenceCount: 5,
  },
};

export const historicalHangKnowledgeInputs: readonly AttackKnowledgeCompilerInput[] = [
  {
    source: {
      privateSourceReference: "private://authorized-history/application-worker-layout-hang",
      privateLabels: ["private-lab-alias", "192.0.2.44"],
      sourceClass: "historical",
      sourceHash: APPLICATION_SOURCE_HASH,
      observedAt: "2026-07-13T12:37:41.000Z",
      evidenceCount: 4,
    },
    knowledge: applicationLayoutDumpHang,
    confidence: 0.96,
  },
  {
    source: {
      privateSourceReference: "private://authorized-history/kernel-transition-v2-hang",
      privateLabels: ["private-lab-alias", "192.0.2.44"],
      sourceClass: "historical",
      sourceHash: KERNEL_V2_SOURCE_HASH,
      observedAt: "2026-07-20T09:03:00.000Z",
      evidenceCount: 5,
    },
    knowledge: kernelTransitionV2Hang,
    confidence: 0.98,
  },
  {
    source: {
      privateSourceReference: "private://authorized-history/kernel-transition-v5-hang",
      privateLabels: ["private-lab-alias", "192.0.2.44"],
      sourceClass: "historical",
      sourceHash: KERNEL_V5_SOURCE_HASH,
      observedAt: "2026-07-20T10:19:16.000Z",
      evidenceCount: 5,
    },
    knowledge: kernelTransitionV5Hang,
    confidence: 0.98,
  },
] as const;

export const historicalHangReconciliation = {
  schemaVersion: 1,
  operatorReportedAggregateResetMinimum: OPERATOR_REPORTED_RESET_MINIMUM,
  exactEvidencedResetMinimum: 2,
  minimumUnattributedResets: 9,
  exactProcedureBundles: 3,
  unresolvedOperatorConfirmations: [
    "Attribute the remaining reset episodes to exact procedure hashes and observed state transitions",
    "Confirm which call in the two-call non-returning script-execution sequence caused the first application-worker hang",
    "Confirm whether additional internal-layout printing episodes used the exact reviewed script or another version",
    "Separate stale-layout crashes from application-worker hangs that required a reset",
    "Confirm whether the later kernel-transition hang was followed by a reset after the preserved evidence ends",
    "Separate long-lived child-process telemetry stalls from application-worker or host recovery events",
  ],
} as const;
