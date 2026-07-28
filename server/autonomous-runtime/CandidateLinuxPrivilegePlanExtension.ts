import type { PlannedStep } from "../command-runtime";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_CLASS,
  AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS,
  AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
  createAutonomousLinuxPrivilegeActionArguments,
} from "./CandidateLinuxPrivilegeContinuation";

/**
 * Builds only the candidate-bound continuation after the independently
 * identified user session and hash-only user proof already exist.
 *
 * `dependencyOrdinal` is the existing user-proof step. The returned ordinals
 * are intentionally relative to the caller's complete plan and form:
 * user proof -> privilege -> independent root identity -> root proof -> cleanup.
 */
export function buildCandidateLinuxPrivilegeContinuationSteps(input: Readonly<{
  exactTarget: string;
  postExploitSpecId: string;
  sessionArtifactId: string;
  assignedAgentId: string;
  dependencyOrdinal: number;
}>): readonly PlannedStep[] {
  if (!Number.isSafeInteger(input.dependencyOrdinal)
    || input.dependencyOrdinal < 0) {
    throw new RangeError("Privilege continuation dependency ordinal is invalid");
  }
  const privilegeOrdinal = input.dependencyOrdinal + 1;
  const rootProofOrdinal = privilegeOrdinal + 1;
  const cleanupOrdinal = rootProofOrdinal + 1;
  const privilege: PlannedStep = Object.freeze({
    phase: "privilege_escalation",
    title: `Attempt the one approved privilege path — ${input.exactTarget}`,
    objective:
      "Use the candidate-specific fixture operation, then independently confirm whether the session became root.",
    explanation:
      "The agent is not opening a general shell. It asks the one reviewed local fixture operation to attempt its approved privilege path, then a separate identity endpoint verifies the actual account and numeric user ID.",
    rationale:
      "A privilege response is only an acknowledgement. Root is accepted only when a different observer proves principal root with UID and GID zero.",
    successCriteria: Object.freeze([
      "The fixed privilege operation is acknowledged.",
      "A separate root-identity observer verifies principal root, uid 0, and gid 0.",
    ]),
    dependencyOrdinals: Object.freeze([input.dependencyOrdinal]),
    assignedAgentId: input.assignedAgentId,
    riskClass: "critical",
    reversibility:
      "The candidate session is lease-fenced and a fixed cleanup operation closes it; no persistence is installed.",
    action: Object.freeze({
      actionType: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
      actionClass: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
      target: input.exactTarget,
      arguments: createAutonomousLinuxPrivilegeActionArguments({
        actionType: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
        postExploitSpecId: input.postExploitSpecId,
        sessionArtifactId: input.sessionArtifactId,
      }),
      intentSummary:
        `Attempt the one candidate-bound privilege path on ${input.exactTarget}, then independently verify root identity`,
      kind: "tool",
      idempotent: false,
      destructive: false,
    }),
  });
  const rootProof: PlannedStep = Object.freeze({
    phase: "root_access_proof",
    title: `Prove the root objective without collecting the flag — ${input.exactTarget}`,
    objective:
      "Confirm access to exactly /root/root.txt using only its SHA-256 and byte count.",
    explanation:
      "After root identity is independently verified, the local fixture returns a fingerprint and file size for the one declared root flag. It never returns or stores the flag text.",
    rationale:
      "A hash-only proof demonstrates the disposable root objective while minimizing retained target data.",
    successCriteria: Object.freeze([
      "A verified hash-only proof exists for /root/root.txt.",
      "No root flag content appears in logs, evidence, runtime receipts, or memory.",
    ]),
    dependencyOrdinals: Object.freeze([privilegeOrdinal]),
    assignedAgentId: input.assignedAgentId,
    riskClass: "critical",
    reversibility:
      "This exact proof is read-only and retains only a receipt hash, file hash, byte count, and declared path.",
    action: Object.freeze({
      actionType: AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
      actionClass: AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_CLASS,
      target: input.exactTarget,
      arguments: createAutonomousLinuxPrivilegeActionArguments({
        actionType: AUTONOMOUS_LINUX_ROOT_FLAG_PROOF_ACTION_TYPE,
        postExploitSpecId: input.postExploitSpecId,
        sessionArtifactId: input.sessionArtifactId,
      }),
      intentSummary:
        `Create one hash-only /root/root.txt access proof for ${input.exactTarget}`,
      kind: "tool",
      idempotent: true,
      destructive: false,
    }),
  });
  const cleanup: PlannedStep = Object.freeze({
    phase: "cleanup",
    title: `Close the candidate session — ${input.exactTarget}`,
    objective:
      "Close the one candidate-bound local fixture session and release its fenced lease.",
    explanation:
      "The fixed cleanup endpoint closes the narrow session after the proof is retained. It cannot run an arbitrary command or delete target data.",
    rationale:
      "Durable cleanup prevents an orphaned local session after completion, cancellation, or restart.",
    successCriteria: Object.freeze([
      "The candidate session is closed.",
      "No active SessionArtifact lease remains.",
    ]),
    dependencyOrdinals: Object.freeze([rootProofOrdinal]),
    assignedAgentId: input.assignedAgentId,
    riskClass: "medium",
    reversibility:
      "Cleanup closes only the local candidate session reference and does not alter target files.",
    action: Object.freeze({
      actionType: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
      actionClass: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_CLASS,
      target: input.exactTarget,
      arguments: createAutonomousLinuxPrivilegeActionArguments({
        actionType: AUTONOMOUS_LINUX_SESSION_CLEANUP_ACTION_TYPE,
        postExploitSpecId: input.postExploitSpecId,
        sessionArtifactId: input.sessionArtifactId,
      }),
      intentSummary:
        `Close the candidate-bound post-exploit session for ${input.exactTarget}`,
      kind: "tool",
      idempotent: true,
      destructive: false,
    }),
  });
  // The computed cleanup ordinal documents the full sequence and prevents a
  // future accidental off-by-one edit from silently changing dependencies.
  if (cleanupOrdinal !== input.dependencyOrdinal + 3) {
    throw new Error("Privilege continuation ordinal invariant failed");
  }
  return Object.freeze([privilege, rootProof, cleanup]);
}
