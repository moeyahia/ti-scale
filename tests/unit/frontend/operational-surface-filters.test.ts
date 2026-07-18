import { describe, expect, test } from "bun:test";
import { buildSelectFilterPatch } from "../../../src/features/runs/OperationalSurface";

describe("Operational surface select filters", () => {
  test("resets a named collection cursor when its filter changes", () => {
    expect(buildSelectFilterPatch("status", "healthy", ["mcpCursor"])).toEqual({
      status: "healthy",
      mcpCursor: undefined,
    });
  });

  test("clears a filter without overwriting the filter key through a malformed reset list", () => {
    expect(buildSelectFilterPatch("status", "", ["status", "mcpCursor"])).toEqual({
      status: undefined,
      mcpCursor: undefined,
    });
  });
});
