import { describe, expect, test } from "bun:test";
import express from "express";
import { SPA_DOCUMENT_ROUTE, V2_API_TREE_ROUTE } from "../expressRoutePatterns";

describe("Express 5 terminal route boundaries", () => {
  test("registers both RegExp routes without the removed anonymous wildcard grammar", () => {
    const app = express();

    expect(() => app.all(V2_API_TREE_ROUTE, (_request, response) => response.sendStatus(503))).not.toThrow();
    expect(() => app.get(SPA_DOCUMENT_ROUTE, (_request, response) => response.sendStatus(200))).not.toThrow();
  });

  test("matches the complete V2 API tree without capturing lookalike routes", () => {
    expect(V2_API_TREE_ROUTE.test("/api/v2")).toBe(true);
    expect(V2_API_TREE_ROUTE.test("/api/v2/health")).toBe(true);
    expect(V2_API_TREE_ROUTE.test("/api/v2/events/stream")).toBe(true);
    expect(V2_API_TREE_ROUTE.test("/api/v20")).toBe(false);
    expect(V2_API_TREE_ROUTE.test("/api/v2ish/health")).toBe(false);
  });

  test("includes root and deep client routes for history fallback", () => {
    expect(SPA_DOCUMENT_ROUTE.test("/")).toBe(true);
    expect(SPA_DOCUMENT_ROUTE.test("/missions/mission-1/runs/run-1")).toBe(true);
  });
});
