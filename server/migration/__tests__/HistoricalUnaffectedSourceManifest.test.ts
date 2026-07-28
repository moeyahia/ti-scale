import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
  parseHistoricalSourceRootConfiguration,
} from "../HistoricalSourceRootConfiguration";

const COMPLETE_MANIFEST = resolve(
  "deployment/runtime-config/historical-source-roots.v2.json",
);
const UNAFFECTED_MANIFEST = resolve(
  "deployment/runtime-config/historical-source-roots.unaffected-delta.v2.json",
);
const REVIEW_PLAN = resolve(
  "docs/historical-unaffected-delta-import-plan.md",
);
const EXCLUDED_ROOT_ID = "historical-htb-workspaces";
const REVIEWED_UNAFFECTED_SHA256 =
  "aac50e19e8176ef0e5f08c2cf22f56eb46584d81b94fd8882d1e2722d08dba60";

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function parse(path: string) {
  return parseHistoricalSourceRootConfiguration(
    JSON.parse(readFileSync(path, "utf8")) as unknown,
  );
}

describe("reviewed unaffected historical delta source manifest", () => {
  test("pins the exact nine-root v2 byte sequence", () => {
    expect(sha256(UNAFFECTED_MANIFEST)).toBe(REVIEWED_UNAFFECTED_SHA256);

    const manifest = parse(UNAFFECTED_MANIFEST);
    expect(manifest.schemaVersion).toBe(
      HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
    );
    expect(manifest.configurationVersion).toBe(
      "historical-unaffected-delta-2026.07.22-v1",
    );
    expect(manifest.roots).toHaveLength(9);
    expect(manifest.roots.filter(({ mode }) => mode === "children")).toHaveLength(2);
    expect(manifest.roots.filter(({ mode }) => mode === "history-root")).toHaveLength(7);
    expect(manifest.roots.every(({ required }) => required)).toBeTrue();
  });

  test("is the complete reviewed v2 boundary excluding only the blocked HTB workspace root", () => {
    const complete = parse(COMPLETE_MANIFEST);
    const unaffected = parse(UNAFFECTED_MANIFEST);
    const excluded = complete.roots.filter(({ id }) => id === EXCLUDED_ROOT_ID);
    const expected = complete.roots.filter(({ id }) => id !== EXCLUDED_ROOT_ID);

    expect(excluded).toEqual([{
      id: EXCLUDED_ROOT_ID,
      path: "/var/lib/chillspwn/workspaces/htb/boxes",
      mode: "children",
      required: true,
    }]);
    expect(unaffected.roots).toEqual(expected);
    expect(unaffected.roots.some(({ id }) => id === EXCLUDED_ROOT_ID)).toBeFalse();
  });

  test("documents a hash-bound dry run without publishing an execute command", () => {
    const plan = readFileSync(REVIEW_PLAN, "utf8");

    expect(plan).toContain(REVIEWED_UNAFFECTED_SHA256);
    expect(plan).toContain("bun run history:plan-delta --");
    expect(plan).toContain("bun run history:migrate-configured --");
    expect(plan).toContain("--acknowledge-verified-reference");
    expect(plan).toContain("--acknowledge-attack-knowledge-only");
    expect(plan).toContain("--dry-run");
    expect(plan).not.toMatch(/^\s*--execute\s*$/mu);
    expect(plan).toContain("No execute/import was run");
  });
});
