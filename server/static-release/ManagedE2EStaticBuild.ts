import {
  existsSync,
  lstatSync,
  readdirSync,
  realpathSync,
  rmSync,
} from "node:fs";
import {
  isAbsolute,
  resolve,
  sep,
} from "node:path";

const DEFAULT_MANAGED_E2E_ROOT = "/tmp/ti-scale-e2e-data";
const BUILD_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/u;

export interface ManagedE2EStaticBuildOptions {
  readonly baseRoot?: string;
  readonly requireBuiltArtifact?: boolean;
}

function normalizedRunId(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/gu, "-").slice(0, 120) || "unnamed-run";
}

function requireRealDirectory(path: string, label: string): void {
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || realpathSync(path) !== path
  ) {
    throw new Error(`${label} must be a real directory`);
  }
}

/**
 * Resolve the only mutable static directory accepted by a Playwright-managed
 * release-profile process. The directory is generated for one E2E invocation,
 * served directly, and deleted by its owning launcher when the server exits.
 *
 * This boundary is deliberately disjoint from StaticArtifactReleaseStore:
 * browser tests neither publish a production release nor retain a prior copy.
 */
export function resolveManagedE2EStaticBuild(
  environment: Readonly<Record<string, string | undefined>>,
  options: ManagedE2EStaticBuildOptions = {},
): string | undefined {
  const configured = environment.TI_SCALE_DIST_ROOT?.trim();
  if (!configured) return undefined;
  if (!isAbsolute(configured)) {
    throw new Error("TI_SCALE_DIST_ROOT must be an absolute managed E2E path");
  }
  if (environment.TI_SCALE_STATIC_RELEASE_ROOT?.trim()) {
    throw new Error(
      "A managed E2E static build cannot be combined with a production static release root",
    );
  }
  if (
    environment.TI_SCALE_PREVIEW !== "true"
    || environment.TI_SCALE_SERVE_STATIC !== "true"
  ) {
    throw new Error(
      "TI_SCALE_DIST_ROOT is test-only and requires preview static serving",
    );
  }

  const runId = environment.TI_SCALE_E2E_RUN_ID?.trim();
  const buildId = environment.TI_SCALE_E2E_STATIC_BUILD_ID?.trim();
  if (!runId || !buildId || !BUILD_ID.test(buildId)) {
    throw new Error(
      "TI_SCALE_DIST_ROOT requires one valid managed E2E run and static build ID",
    );
  }
  const expectedPrefix = `e2e-${normalizedRunId(runId).slice(0, 108)}-`;
  if (
    !buildId.startsWith(expectedPrefix)
    || !/^\d+$/u.test(buildId.slice(expectedPrefix.length))
  ) {
    throw new Error("The managed E2E static build ID is not bound to this run");
  }

  const baseRoot = resolve(options.baseRoot ?? DEFAULT_MANAGED_E2E_ROOT);
  requireRealDirectory(baseRoot, "The managed E2E root");
  const expected = resolve(baseRoot, `static-build-${buildId}`);
  const dist = resolve(configured);
  if (dist !== expected || !dist.startsWith(`${baseRoot}${sep}`)) {
    throw new Error(
      "TI_SCALE_DIST_ROOT must exactly match this invocation's managed E2E build path",
    );
  }

  if (existsSync(dist)) requireRealDirectory(dist, "The managed E2E static build");
  if (options.requireBuiltArtifact) {
    requireRealDirectory(dist, "The managed E2E static build");
    const indexPath = resolve(dist, "index.html");
    const index = lstatSync(indexPath);
    if (!index.isFile() || index.isSymbolicLink()) {
      throw new Error("The managed E2E static build must contain a real index.html");
    }
  }
  return dist;
}

/**
 * Remove only direct static build output owned by one completed E2E run.
 * Playwright may terminate a managed process group before the launcher's
 * `finally` executes, so its global teardown is the authoritative disposer.
 */
export function disposeManagedE2EStaticBuilds(
  runIdValue: string,
  baseRootValue = DEFAULT_MANAGED_E2E_ROOT,
): readonly string[] {
  const runId = normalizedRunId(runIdValue.trim());
  const baseRoot = resolve(baseRootValue);
  if (!existsSync(baseRoot)) return [];
  requireRealDirectory(baseRoot, "The managed E2E root");
  const prefix = `static-build-e2e-${runId.slice(0, 108)}-`;
  const removed: string[] = [];
  for (const entry of readdirSync(baseRoot, { withFileTypes: true })) {
    if (
      !entry.name.startsWith(prefix)
      || !/^\d+$/u.test(entry.name.slice(prefix.length))
    ) continue;
    const path = resolve(baseRoot, entry.name);
    if (!path.startsWith(`${baseRoot}${sep}`)) {
      throw new Error("A managed E2E static cleanup path escaped its root");
    }
    requireRealDirectory(path, "The managed E2E static build");
    rmSync(path, { recursive: true, force: true });
    removed.push(path);
  }
  return Object.freeze(removed);
}
