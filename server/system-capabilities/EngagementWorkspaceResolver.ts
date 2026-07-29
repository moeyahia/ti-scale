import { readdir, realpath, stat } from "node:fs/promises";
import {
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;

export type EngagementWorkspaceResolutionCode =
  | "resolved"
  | "logical_root_unmapped"
  | "runtime_root_unavailable"
  | "case_ambiguous"
  | "path_unavailable"
  | "path_escape";

export interface EngagementWorkspaceMapping {
  /** Stable path used in plans and imported engagement records. */
  readonly logicalRoot: string;
  /** Worker-visible root. This is configuration, never model-provided input. */
  readonly runtimeRoot: string;
}

export interface EngagementWorkspaceResolution {
  readonly schemaVersion: "ti-scale.engagement-workspace-resolution.v1";
  readonly status: "resolved" | "unavailable";
  readonly code: EngagementWorkspaceResolutionCode;
  readonly requestedPath: string;
  readonly logicalRoot: string | null;
  readonly caseAdjusted: boolean;
  readonly resolvedPath: string | null;
  readonly explanation: string;
  readonly remediation: string | null;
}

export interface EngagementWorkspaceEnvironment {
  realpath(path: string): Promise<string>;
  list(path: string): Promise<readonly string[]>;
  isDirectory(path: string): Promise<boolean>;
}

function defaultEnvironment(): EngagementWorkspaceEnvironment {
  return {
    realpath,
    async list(path) {
      return readdir(path);
    },
    async isDirectory(path) {
      try {
        return (await stat(path)).isDirectory();
      } catch {
        return false;
      }
    },
  };
}

function normalizedAbsolute(path: string, label: string): string {
  if (!isAbsolute(path) || CONTROL_CHARACTERS.test(path)) {
    throw new Error(`${label} must be an absolute path without control characters`);
  }
  return resolve(path);
}

function inside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

function pathSegments(root: string, candidate: string): readonly string[] {
  const path = relative(root, candidate);
  return path === "" ? [] : path.split(sep).filter(Boolean);
}

function unavailable(input: {
  code: Exclude<EngagementWorkspaceResolutionCode, "resolved">;
  requestedPath: string;
  logicalRoot?: string;
  caseAdjusted?: boolean;
  explanation: string;
  remediation: string;
}): EngagementWorkspaceResolution {
  return {
    schemaVersion: "ti-scale.engagement-workspace-resolution.v1",
    status: "unavailable",
    code: input.code,
    requestedPath: input.requestedPath,
    logicalRoot: input.logicalRoot ?? null,
    caseAdjusted: input.caseAdjusted ?? false,
    resolvedPath: null,
    explanation: input.explanation,
    remediation: input.remediation,
  };
}

/**
 * Resolves a plan's stable engagement path into one configured worker root.
 * It never creates a directory and never falls back to a similarly named path
 * outside the mapping. Case-insensitive matching is limited to one directory
 * level at a time so an existing `reapertwo` workspace is reused instead of
 * silently creating a second `ReaperTwo` tree.
 */
export class EngagementWorkspaceResolver {
  private readonly mappings: readonly EngagementWorkspaceMapping[];
  private readonly environment: EngagementWorkspaceEnvironment;

  constructor(
    mappings: readonly EngagementWorkspaceMapping[],
    options: { readonly environment?: EngagementWorkspaceEnvironment } = {},
  ) {
    if (mappings.length < 1 || mappings.length > 32) {
      throw new Error("Workspace resolver requires 1-32 trusted mappings");
    }
    const normalized = mappings.map((mapping) => ({
      logicalRoot: normalizedAbsolute(mapping.logicalRoot, "Workspace logical root"),
      runtimeRoot: normalizedAbsolute(mapping.runtimeRoot, "Workspace runtime root"),
    }));
    const logicalRoots = new Set(normalized.map(({ logicalRoot }) => logicalRoot));
    if (logicalRoots.size !== normalized.length) {
      throw new Error("Workspace logical roots must be unique");
    }
    this.mappings = normalized.sort((left, right) => right.logicalRoot.length - left.logicalRoot.length);
    this.environment = options.environment ?? defaultEnvironment();
  }

  async resolve(requestedPath: string): Promise<EngagementWorkspaceResolution> {
    const normalizedRequested = normalizedAbsolute(requestedPath, "Requested workspace path");
    const mapping = this.mappings.find(({ logicalRoot }) => inside(logicalRoot, normalizedRequested));
    if (!mapping) {
      return unavailable({
        code: "logical_root_unmapped",
        requestedPath: normalizedRequested,
        explanation: "The requested engagement path is outside every configured worker workspace mapping.",
        remediation: "Select an engagement path under a reviewed logical workspace root; do not substitute an arbitrary host path.",
      });
    }

    let canonicalRuntimeRoot: string;
    try {
      canonicalRuntimeRoot = await this.environment.realpath(mapping.runtimeRoot);
    } catch {
      return unavailable({
        code: "runtime_root_unavailable",
        requestedPath: normalizedRequested,
        logicalRoot: mapping.logicalRoot,
        explanation: "The configured worker workspace root is missing or inaccessible.",
        remediation: "Restore the configured workspace mount and worker permissions, then resolve the engagement again.",
      });
    }
    if (!await this.environment.isDirectory(canonicalRuntimeRoot)) {
      return unavailable({
        code: "runtime_root_unavailable",
        requestedPath: normalizedRequested,
        logicalRoot: mapping.logicalRoot,
        explanation: "The configured worker workspace root is not an accessible directory.",
        remediation: "Repair the reviewed workspace mount; do not redirect the run to an untracked directory.",
      });
    }

    let current = canonicalRuntimeRoot;
    let caseAdjusted = false;
    for (const requestedSegment of pathSegments(mapping.logicalRoot, normalizedRequested)) {
      let entries: readonly string[];
      try {
        entries = await this.environment.list(current);
      } catch {
        return unavailable({
          code: "path_unavailable",
          requestedPath: normalizedRequested,
          logicalRoot: mapping.logicalRoot,
          caseAdjusted,
          explanation: "The worker cannot inspect the configured engagement path with its current filesystem permissions.",
          remediation: "Repair the mapped workspace permissions, then repeat resolution without changing the requested engagement identity.",
        });
      }
      const exact = entries.find((entry) => entry === requestedSegment);
      const insensitive = exact
        ? [exact]
        : entries.filter((entry) => entry.toLocaleLowerCase("en-US") === requestedSegment.toLocaleLowerCase("en-US"));
      if (insensitive.length > 1) {
        return unavailable({
          code: "case_ambiguous",
          requestedPath: normalizedRequested,
          logicalRoot: mapping.logicalRoot,
          caseAdjusted,
          explanation: `The workspace contains multiple case variants for the path segment “${requestedSegment}”, so Ti-Scale cannot select one safely.`,
          remediation: "Reconcile the duplicate case variants outside an active run, preserving their provenance, then resolve the path again.",
        });
      }
      const matched = insensitive[0];
      if (!matched) {
        return unavailable({
          code: "path_unavailable",
          requestedPath: normalizedRequested,
          logicalRoot: mapping.logicalRoot,
          caseAdjusted,
          explanation: `The mapped workspace does not contain the requested path segment “${requestedSegment}”.`,
          remediation: "Create or import the engagement through the reviewed workspace service before dispatching a tool; do not write to the inaccessible logical path.",
        });
      }
      caseAdjusted ||= matched !== requestedSegment;
      current = join(current, matched);
    }

    let canonicalResolved: string;
    try {
      canonicalResolved = await this.environment.realpath(current);
    } catch {
      return unavailable({
        code: "path_unavailable",
        requestedPath: normalizedRequested,
        logicalRoot: mapping.logicalRoot,
        caseAdjusted,
        explanation: "The mapped engagement path disappeared or became inaccessible during resolution.",
        remediation: "Restore the engagement directory and repeat the resolution before any tool starts.",
      });
    }
    if (!inside(canonicalRuntimeRoot, canonicalResolved)) {
      return unavailable({
        code: "path_escape",
        requestedPath: normalizedRequested,
        logicalRoot: mapping.logicalRoot,
        caseAdjusted,
        explanation: "The mapped engagement path resolves outside the configured worker workspace root.",
        remediation: "Remove or review the escaping link and restore an in-root engagement workspace before dispatch.",
      });
    }
    if (!await this.environment.isDirectory(canonicalResolved)) {
      return unavailable({
        code: "path_unavailable",
        requestedPath: normalizedRequested,
        logicalRoot: mapping.logicalRoot,
        caseAdjusted,
        explanation: "The mapped engagement path is not an accessible directory.",
        remediation: "Restore the expected engagement directory before dispatching a workspace-bound tool.",
      });
    }
    return {
      schemaVersion: "ti-scale.engagement-workspace-resolution.v1",
      status: "resolved",
      code: "resolved",
      requestedPath: normalizedRequested,
      logicalRoot: mapping.logicalRoot,
      caseAdjusted,
      resolvedPath: canonicalResolved,
      explanation: caseAdjusted
        ? "The engagement was resolved to the existing worker workspace using its recorded filesystem casing."
        : "The engagement path resolved exactly inside the configured worker workspace.",
      remediation: null,
    };
  }
}
