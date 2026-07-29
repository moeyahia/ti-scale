import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { resolveConfig } from "vite";
import {
  assertProductionStaticOrigins,
  FORBIDDEN_PRODUCTION_API_ORIGINS,
} from "../../../scripts/production-static-origin-guard";

const viteConfig = readFileSync(new URL("../../../vite.config.ts", import.meta.url), "utf8");
const apiClient = readFileSync(new URL("../../../src/data/api/client.ts", import.meta.url), "utf8");
const applicationRoot = resolve(import.meta.dir, "../../..");

describe("production static API origin", () => {
  test("keeps the 43141 fallback inside the split-development server configuration", async () => {
    expect(viteConfig).toContain('command === "serve" && !isPreview');
    expect(viteConfig).toContain("productionStaticOriginGuard()");
    expect(viteConfig).not.toContain("const apiOrigin =");
    expect(apiClient).toContain("fetch(path");
    expect(apiClient).not.toContain("VITE_TI_SCALE_API_ORIGIN");

    const production = await resolveConfig(
      { root: applicationRoot, configFile: resolve(applicationRoot, "vite.config.ts") },
      "build",
      "production",
    );
    expect(production.server.proxy).toBeUndefined();
    expect(production.envPrefix).toBe("VITE_TI_SCALE_");

    const preview = await resolveConfig(
      { root: applicationRoot, configFile: resolve(applicationRoot, "vite.config.ts") },
      "serve",
      "production",
      "production",
      true,
    );
    expect(preview.server.proxy).toBeUndefined();

    const development = await resolveConfig(
      { root: applicationRoot, configFile: resolve(applicationRoot, "vite.config.ts") },
      "serve",
      "development",
    );
    expect(development.server.proxy).toEqual({
      "/api/v2": {
        target: "http://127.0.0.1:43141",
        changeOrigin: false,
      },
      "/api/v2/events": {
        target: "http://127.0.0.1:43141",
        changeOrigin: false,
      },
    });
  });

  test("accepts same-origin production API paths", () => {
    expect(() => assertProductionStaticOrigins([
      {
        fileName: "assets/index.js",
        content: [
          'fetch("/api/v2/auth/session",{credentials:"same-origin"})',
          'new EventSource("/api/v2/events/stream")',
        ].join(";"),
      },
      {
        fileName: "index.html",
        content: '<script type="module" src="/assets/index.js"></script>',
      },
    ])).not.toThrow();
  });

  for (const origin of FORBIDDEN_PRODUCTION_API_ORIGINS) {
    test(`rejects ${origin} in an emitted production artifact`, () => {
      expect(() => assertProductionStaticOrigins([
        {
          fileName: "assets/index.js",
          content: `fetch("${origin}/api/v2/auth/session")`,
        },
      ])).toThrow("Production static artifacts contain an absolute or build-time API origin");
    });
  }

  test("also rejects the development origin when it leaks into binary-backed output", () => {
    expect(() => assertProductionStaticOrigins([
      {
        fileName: "assets/index.js.map",
        content: new TextEncoder().encode(
          '{"sourcesContent":["http://127.0.0.1:43141/api/v2/events"]}',
        ),
      },
    ])).toThrow("assets/index.js.map: http://127.0.0.1:43141");
  });

  test("rejects any absolute API v2 dependency, including the nominal production port", () => {
    expect(() => assertProductionStaticOrigins([
      {
        fileName: "assets/index.js",
        content: 'fetch("http://127.0.0.1:3132/api/v2/agents")',
      },
      {
        fileName: "assets/events.js",
        content: 'new EventSource("https://command.example.test/api/v2/events/stream")',
      },
    ])).toThrow("absolute API reference");
  });

  test("rejects a build-time API origin token copied through a public asset", () => {
    expect(() => assertProductionStaticOrigins([
      {
        fileName: "runtime-config.json",
        content: '{"VITE_TI_SCALE_API_ORIGIN":"http://127.0.0.1:43141"}',
      },
    ])).toThrow("runtime-config.json: build-time API origin token");
  });
});
