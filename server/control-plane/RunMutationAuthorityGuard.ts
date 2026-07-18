import { RuntimeRepository } from "../command-runtime/RuntimeRepository";
import type { SqliteDatabase } from "../db";
import { MissionRepository } from "../missions/MissionRepository";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
  type ControlPlaneLease,
} from "./ControlPlaneLeaseService";

export type RunMutationAuthorityMode = "ownership" | "lease";

export interface RunMutationScope {
  readonly missionId: string;
  readonly runId: string;
}

export interface RunMutationLeaseRequest extends RunMutationScope {
  readonly actorId: string;
}

/**
 * Trusted server-side callback implemented by the runtime that owns the raw
 * control-plane token. It must call ControlPlaneLeaseService with that token
 * and return only the resulting non-secret proof.
 */
export type AssertRunMutationLease = (
  request: RunMutationLeaseRequest,
) => ControlPlaneLease | undefined;

export interface AuthorizedRunMutation {
  readonly scope: RunMutationScope;
  readonly mode: RunMutationAuthorityMode;
  /** Recheck immediately inside the idempotency transaction. */
  assertCurrent(): void;
}

export interface RunMutationAuthorityErrorDescriptor {
  readonly status: number;
  readonly code: string;
  readonly category: "not_found" | "policy_denied" | "state_conflict";
  readonly retryable: boolean;
  readonly remediation: string;
}

export function describeRunMutationAuthorityError(
  error: ControlPlaneLeaseError,
): RunMutationAuthorityErrorDescriptor {
  if (error.code === "run_not_found") {
    return {
      status: 404,
      code: "control_plane_run_not_found",
      category: "not_found",
      retryable: false,
      remediation: "Refresh the mission and use a canonical run link.",
    };
  }
  if (error.code === "control_plane_mismatch") {
    return {
      status: 409,
      code: "control_plane_mismatch",
      category: "policy_denied",
      retryable: false,
      remediation: "Open this run through its owning control plane; imported legacy runs remain read-only in Ti-Scale.",
    };
  }
  if (error.code === "lease_missing") {
    return {
      status: 409,
      code: "control_plane_lease_missing",
      category: "state_conflict",
      retryable: false,
      remediation: "Use the active V2 runtime controller for this mutation; the HTTP boundary cannot mint or infer lease authority.",
    };
  }
  if (error.code === "lease_expired") {
    return {
      status: 409,
      code: "control_plane_lease_expired",
      category: "state_conflict",
      retryable: true,
      remediation: "Let the owning runtime reacquire and heartbeat the run lease, then retry from refreshed state.",
    };
  }
  return {
    status: 409,
    code: error.code === "lease_fence_invalid"
      ? "control_plane_lease_fence_invalid"
      : "control_plane_lease_authority_invalid",
    category: "state_conflict",
    retryable: error.retryable,
    remediation: "Refresh the run and retry only through the current fenced V2 runtime controller.",
  };
}

/**
 * Small shared boundary for run-scoped V2 mutations. Ownership-only mode is
 * reserved for deterministic derived-state recomputation. Every behavioral or
 * execution-semantic mutation also requires a proof from the active runtime;
 * an absent callback fails closed and raw HTTP headers are never consulted.
 */
export class RunMutationAuthorityGuard {
  private readonly runs: RuntimeRepository;
  private readonly missions: MissionRepository;
  private readonly leases: ControlPlaneLeaseService;

  constructor(
    database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.runs = new RuntimeRepository(database);
    this.missions = new MissionRepository(database);
    this.leases = new ControlPlaneLeaseService(database);
  }

  private ownedScope(runId: string): RunMutationScope {
    const run = this.runs.getControlPlaneOwnership(runId);
    if (!run) throw new ControlPlaneLeaseError("run_not_found", `Run ${runId} does not exist`);
    const mission = this.missions.getControlPlaneOwnership(run.missionId);
    if (
      !mission
      || run.controlPlane !== "ti_scale"
      || mission.controlPlane !== "ti_scale"
    ) {
      throw new ControlPlaneLeaseError(
        "control_plane_mismatch",
        `Run ${runId} is not exclusively owned by Ti-Scale`,
      );
    }
    return { missionId: run.missionId, runId };
  }

  authorize(input: {
    readonly runId: string;
    readonly actorId: string;
    readonly mode: RunMutationAuthorityMode;
    readonly assertLease?: AssertRunMutationLease;
  }): AuthorizedRunMutation {
    const scope = this.ownedScope(input.runId);
    if (input.mode === "ownership") {
      return {
        scope,
        mode: input.mode,
        assertCurrent: () => {
          const current = this.ownedScope(scope.runId);
          if (current.missionId !== scope.missionId) {
            throw new ControlPlaneLeaseError("control_plane_mismatch", `Run ${scope.runId} changed mission ownership`);
          }
        },
      };
    }

    if (!input.assertLease) {
      throw new ControlPlaneLeaseError(
        "lease_missing",
        `Run ${scope.runId} has no server-side mutation-authority resolver`,
      );
    }
    const assertLease = input.assertLease;
    const resolveCurrentProof = (): ControlPlaneLease => {
      const proof = assertLease({ ...scope, actorId: input.actorId });
      if (!proof) {
        throw new ControlPlaneLeaseError(
          "lease_missing",
          `Run ${scope.runId} has no active runtime mutation authority`,
        );
      }
      if (proof.runId !== scope.runId || proof.controlPlane !== "ti_scale") {
        throw new ControlPlaneLeaseError(
          "lease_fence_invalid",
          `Run ${scope.runId} received a lease proof for another control-plane scope`,
        );
      }
      return this.leases.assertCurrentLeaseProof(proof, this.clock());
    };
    const initialProof = resolveCurrentProof();
    return {
      scope,
      mode: input.mode,
      assertCurrent: () => {
        const current = this.ownedScope(scope.runId);
        if (current.missionId !== scope.missionId) {
          throw new ControlPlaneLeaseError("control_plane_mismatch", `Run ${scope.runId} changed mission ownership`);
        }
        // Refresh the exact proof so a normal heartbeat does not invalidate a
        // healthy long-running mutation. The stable acquisition epoch still
        // fences release/reacquisition or controller takeover.
        const refreshedProof = resolveCurrentProof();
        if (
          refreshedProof.leaseOwner !== initialProof.leaseOwner
          || refreshedProof.acquiredAt !== initialProof.acquiredAt
          || refreshedProof.controlPlane !== initialProof.controlPlane
        ) {
          throw new ControlPlaneLeaseError(
            "lease_fence_invalid",
            `Run ${scope.runId} control-plane controller changed during the mutation`,
            true,
          );
        }
      },
    };
  }
}
