import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
  parseHistoricalSourceRootConfiguration,
} from "../HistoricalSourceRootConfiguration";

const SUPPLEMENTAL_MANIFEST = resolve(
  "deployment/runtime-config/historical-source-roots.supplemental.v2.json",
);
const COMPLETE_MANIFEST = resolve(
  "deployment/runtime-config/historical-source-roots.v2.json",
);
const V1_MANIFEST = resolve(
  "deployment/runtime-config/historical-source-roots.v1.json",
);
const REVIEWED_SUPPLEMENTAL_SHA256 =
  "08a2ab9fcead05295f51d0199ec85431d7ef7c14d8b8b52df5199362b6382f5a";

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function parse(path: string) {
  return parseHistoricalSourceRootConfiguration(
    JSON.parse(readFileSync(path, "utf8")) as unknown,
  );
}

describe("reviewed supplemental-only historical source manifest", () => {
  test("is hash-pinned, strict v2 data and contains no v1 root", () => {
    expect(sha256(SUPPLEMENTAL_MANIFEST)).toBe(REVIEWED_SUPPLEMENTAL_SHA256);
    const supplemental = parse(SUPPLEMENTAL_MANIFEST);
    const v1Paths = new Set(parse(V1_MANIFEST).roots.map(({ path }) => path));

    expect(supplemental.schemaVersion).toBe(
      HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
    );
    expect(supplemental.roots).toHaveLength(8);
    expect(supplemental.roots.filter(({ mode }) => mode === "children")).toHaveLength(1);
    expect(supplemental.roots.filter(({ mode }) => mode === "history-root")).toHaveLength(7);
    expect(supplemental.roots.some(({ path }) => v1Paths.has(path))).toBeFalse();
  });

  test("is exactly the complete v2 manifest minus the two v1 roots", () => {
    const supplemental = parse(SUPPLEMENTAL_MANIFEST);
    const complete = parse(COMPLETE_MANIFEST);
    const v1Paths = new Set(parse(V1_MANIFEST).roots.map(({ path }) => path));
    const expected = complete.roots.filter(({ path }) => !v1Paths.has(path));

    expect(supplemental.roots).toEqual(expected);
  });
});
