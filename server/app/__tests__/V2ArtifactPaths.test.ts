import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { resolveV2ScriptSourceRoot } from "../V2ArtifactPaths";

describe("Ti-Scale artifact path isolation", () => {
  test("derives a stable Ti-Scale-only absolute source namespace from the canonical database", () => {
    expect(resolveV2ScriptSourceRoot("/var/lib/ti-scale/ti-scale.sqlite")).toBe(
      "/var/lib/ti-scale/ti-scale-artifacts/ti-scale/script-sources",
    );
  });

  test("accepts an explicit absolute Ti-Scale namespace and rejects relative or imported roots", () => {
    const database = resolve("/srv/ti-scale/ti-scale/data.sqlite");
    expect(resolveV2ScriptSourceRoot(
      database,
      "/srv/ti-scale/ti-scale-artifacts/script-sources",
    )).toBe("/srv/ti-scale/ti-scale-artifacts/script-sources");
    expect(() => resolveV2ScriptSourceRoot(database, "relative/script-sources"))
      .toThrow("must be an absolute path");
    expect(() => resolveV2ScriptSourceRoot(
      database,
      "/srv/ti-scale/external-import/artifacts/ti-scale",
    )).toThrow("must not reference an external import source");
    expect(() => resolveV2ScriptSourceRoot(database, "/srv/runtime/new-script-store"))
      .toThrow("must include a ti-scale namespace segment");
  });
});
