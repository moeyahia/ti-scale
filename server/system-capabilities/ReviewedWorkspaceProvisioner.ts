import { mkdir, lstat, chmod, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { EngagementWorkspaceMapping } from "./EngagementWorkspaceResolver";

const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

export type ReviewedWorkspaceProvisioningCode =
  | "ready"
  | "provisioned"
  | "logical_root_unmapped"
  | "runtime_root_unavailable"
  | "workspace_depth_unsupported"
  | "case_conflict"
  | "path_conflict"
  | "path_escape"
  | "ownership_mismatch"
  | "unsafe_permissions";

export interface ReviewedWorkspaceProvisioningResult {
  readonly schemaVersion: "ti-scale.reviewed-workspace-provisioning.v1";
  readonly status: "ready" | "unavailable";
  readonly code: ReviewedWorkspaceProvisioningCode;
  readonly logicalWorkspace: string;
  readonly runtimePath: string | null;
  readonly created: boolean;
  readonly explanation: string;
  readonly remediation: string | null;
}

function inside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function unavailable(
  code: Exclude<ReviewedWorkspaceProvisioningCode, "ready" | "provisioned">,
  logicalWorkspace: string,
  explanation: string,
  remediation: string,
): ReviewedWorkspaceProvisioningResult {
  return Object.freeze({
    schemaVersion: "ti-scale.reviewed-workspace-provisioning.v1",
    status: "unavailable",
    code,
    logicalWorkspace,
    runtimePath: null,
    created: false,
    explanation,
    remediation,
  });
}

/**
 * Provisions one exact, deployment-reviewed Autonomous workspace. It is not a
 * general path-creation API: the signed logical path must be exactly one safe
 * child of a signed, existing runtime root. The ordinary mission resolver
 * remains read-only and never creates model- or operator-supplied paths.
 */
export class ReviewedWorkspaceProvisioner {
  constructor(
    private readonly mappings: readonly EngagementWorkspaceMapping[],
    private readonly identity: Readonly<{
      uid: number;
      gid: number;
    }> = Object.freeze({
      uid: process.geteuid?.() ?? process.getuid?.() ?? 0,
      gid: process.getegid?.() ?? process.getgid?.() ?? 0,
    }),
  ) {}

  async provision(logicalWorkspace: string): Promise<ReviewedWorkspaceProvisioningResult> {
    if (!isAbsolute(logicalWorkspace)) {
      return unavailable(
        "logical_root_unmapped",
        logicalWorkspace,
        "The reviewed Autonomous workspace is not an absolute logical path.",
        "Correct and re-sign the Autonomous runtime configuration before startup.",
      );
    }
    const requested = resolve(logicalWorkspace);
    const candidates = this.mappings
      .map((mapping) => ({
        logicalRoot: resolve(mapping.logicalRoot),
        runtimeRoot: resolve(mapping.runtimeRoot),
      }))
      .filter(({ logicalRoot }) => inside(logicalRoot, requested))
      .sort((left, right) => right.logicalRoot.length - left.logicalRoot.length);
    const mapping = candidates[0];
    if (!mapping) {
      return unavailable(
        "logical_root_unmapped",
        requested,
        "The reviewed Autonomous workspace is outside every trusted runtime mapping.",
        "Add the exact logical root to the deployment-pinned workspace mapping and re-attest it.",
      );
    }
    const segments = relative(mapping.logicalRoot, requested).split(sep).filter(Boolean);
    if (segments.length !== 1 || !SAFE_SEGMENT.test(segments[0]!)) {
      return unavailable(
        "workspace_depth_unsupported",
        requested,
        "Automatic provisioning accepts one safe engagement directory directly below the reviewed logical root.",
        "Provision deeper structures through the reviewed engagement importer, then restart readiness.",
      );
    }

    let rootRealPath: string;
    try {
      const rootStat = await lstat(mapping.runtimeRoot);
      if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error("not a direct directory");
      rootRealPath = await realpath(mapping.runtimeRoot);
    } catch {
      return unavailable(
        "runtime_root_unavailable",
        requested,
        "The trusted runtime workspace root is missing, inaccessible, or a symbolic link.",
        "Restore the deployment-owned workspace root as a direct directory before runtime startup.",
      );
    }

    const segment = segments[0]!;
    const destination = join(rootRealPath, segment);
    let rootEntries: readonly string[];
    try {
      rootEntries = await readdir(rootRealPath);
    } catch {
      return unavailable(
        "runtime_root_unavailable",
        requested,
        "The runtime service cannot enumerate the trusted workspace root.",
        "Restore service read/write access to the exact trusted runtime root before startup.",
      );
    }
    const caseMatches = rootEntries
      .filter((entry) => entry.toLocaleLowerCase("en-US") === segment.toLocaleLowerCase("en-US"));
    if (caseMatches.length > 1 || (caseMatches.length === 1 && caseMatches[0] !== segment)) {
      return unavailable(
        "case_conflict",
        requested,
        `The trusted runtime root already contains a conflicting case variant for “${segment}”.`,
        "Reconcile the existing engagement identity and provenance; do not create a duplicate case variant.",
      );
    }

    let created = false;
    try {
      await lstat(destination);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        return unavailable(
          "path_conflict",
          requested,
          "The reviewed workspace path could not be inspected with the service identity.",
          "Repair the exact parent permissions and retry readiness without changing the workspace identity.",
        );
      }
      try {
        await mkdir(destination, { mode: 0o700, recursive: false });
        await chmod(destination, 0o700);
        created = true;
      } catch (createError) {
        if ((createError as NodeJS.ErrnoException).code !== "EEXIST") {
          return unavailable(
            "path_conflict",
            requested,
            "The service could not create the exact reviewed Autonomous workspace.",
            "Restore service ownership of the trusted runtime root, then restart readiness.",
          );
        }
      }
    }

    let destinationStat;
    let destinationRealPath: string;
    try {
      destinationStat = await lstat(destination);
      destinationRealPath = await realpath(destination);
    } catch {
      return unavailable(
        "path_conflict",
        requested,
        "The reviewed workspace disappeared or became inaccessible during attestation.",
        "Restore the exact workspace and repeat readiness before dispatch.",
      );
    }
    if (!destinationStat.isDirectory() || destinationStat.isSymbolicLink()) {
      return unavailable(
        "path_conflict",
        requested,
        "The reviewed workspace path is not a direct directory.",
        "Replace the conflicting file or link with a service-owned engagement directory after preserving provenance.",
      );
    }
    if (!inside(rootRealPath, destinationRealPath)) {
      return unavailable(
        "path_escape",
        requested,
        "The reviewed workspace resolves outside the trusted runtime root.",
        "Remove the escaping path and restore an in-root service-owned workspace.",
      );
    }
    if (destinationStat.uid !== this.identity.uid || destinationStat.gid !== this.identity.gid) {
      return unavailable(
        "ownership_mismatch",
        requested,
        "The reviewed Autonomous workspace is not owned by the runtime service identity.",
        "Correct the exact workspace owner to the Ti-Scale service account; do not broaden filesystem permissions.",
      );
    }
    if ((destinationStat.mode & 0o077) !== 0) {
      return unavailable(
        "unsafe_permissions",
        requested,
        "The reviewed Autonomous workspace is accessible by group or other users.",
        "Set the exact workspace mode to 0700 and repeat readiness.",
      );
    }
    return Object.freeze({
      schemaVersion: "ti-scale.reviewed-workspace-provisioning.v1",
      status: "ready",
      code: created ? "provisioned" : "ready",
      logicalWorkspace: requested,
      runtimePath: destinationRealPath,
      created,
      explanation: created
        ? "Created and attested the exact deployment-reviewed Autonomous workspace with service-only access."
        : "The exact deployment-reviewed Autonomous workspace is present and service-only.",
      remediation: null,
    });
  }
}
