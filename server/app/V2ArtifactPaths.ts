import { basename, dirname, extname, isAbsolute, join, resolve, sep } from "node:path";

const EXTERNAL_SOURCE_SEGMENTS = new Set(["external-import"]);
const EXTERNAL_DATABASE_NAMES = new Set(["kanban.sqlite", "missions.sqlite", "sessions.sqlite"]);
const TI_SCALE_NAMESPACE = /(?:^|[-_.])ti[-_]?scale(?:$|[-_.])/u;

function normalizedSegments(path: string): readonly string[] {
  return path.toLocaleLowerCase("en-US").split(sep).filter(Boolean);
}

function assertNotExternalSourcePath(path: string, label: string): void {
  const segments = normalizedSegments(path);
  const file = basename(path).toLocaleLowerCase("en-US");
  if (segments.some((segment) => EXTERNAL_SOURCE_SEGMENTS.has(segment)) || EXTERNAL_DATABASE_NAMES.has(file)) {
    throw new Error(`${label} must not reference an external import source`);
  }
}

/**
 * Resolves the immutable source store beneath a visibly Ti-Scale-owned namespace.
 * A configured override must be absolute and carry the same namespace marker,
 * preventing a typo from placing source beside imported data.
 */
export function resolveV2ScriptSourceRoot(
  databasePath: string,
  configuredRoot?: string,
): string {
  if (!isAbsolute(databasePath)) {
    throw new Error("Ti-Scale database path must be absolute before deriving artifact storage");
  }
  const canonicalDatabasePath = resolve(databasePath);
  assertNotExternalSourcePath(canonicalDatabasePath, "Ti-Scale database path");

  const configured = configuredRoot?.trim();
  if (configured && !isAbsolute(configured)) {
    throw new Error("TI_SCALE_SCRIPT_SOURCE_ROOT must be an absolute path");
  }
  const databaseStem = basename(
    canonicalDatabasePath,
    extname(canonicalDatabasePath),
  ).replace(/[^A-Za-z0-9._-]/gu, "-") || "canonical";
  const result = resolve(
    configured || join(
      dirname(canonicalDatabasePath),
      "ti-scale-artifacts",
      databaseStem,
      "script-sources",
    ),
  );
  assertNotExternalSourcePath(result, "TI_SCALE_SCRIPT_SOURCE_ROOT");
  if (!normalizedSegments(result).some((segment) => TI_SCALE_NAMESPACE.test(segment))) {
    throw new Error(
      "TI_SCALE_SCRIPT_SOURCE_ROOT must include a ti-scale namespace segment",
    );
  }
  if (result === canonicalDatabasePath) {
    throw new Error("Script source storage cannot overwrite the Ti-Scale database");
  }
  return result;
}
