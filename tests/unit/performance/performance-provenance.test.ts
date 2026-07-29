import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import { resolveConfig } from "vite";
import {
  PERFORMANCE_BUILD_PROVENANCE_SCHEMA,
  PERFORMANCE_SOURCE_PROVENANCE_SCHEMA,
  classifyObservedResourceUrl,
  directoryTreeManifest,
  observedResourceIntegrityFailure,
  performanceBuildBaselinePath,
  performanceEvidenceRunDirectory,
  performanceSourceBaselinePath,
  publishAtomicTextExclusive,
  readPerformanceBuildBaseline,
  readPerformanceSourceBaseline,
  reserveImmutableEvidenceDirectory,
  sameFileTreeSummary,
  sourceTreeManifest,
  staticResponseIntegrityFailures,
  summarizeFileTree,
} from "../../performance/performanceProvenance";

function fixtureRoot(): string {
  return mkdtempSync(join(tmpdir(), "ti-scale-performance-provenance-"));
}

describe("performance provenance", () => {
  test("creates a deterministic complete directory manifest", () => {
    const root = fixtureRoot();
    try {
      mkdirSync(join(root, "assets"));
      writeFileSync(join(root, "index.html"), "<main>Ti-Scale</main>\n");
      writeFileSync(join(root, "assets", "app.js"), "export {};\n");
      const first = directoryTreeManifest(root);
      const second = directoryTreeManifest(root);
      expect(first).toEqual(second);
      expect(first.files.map(({ path }) => path)).toEqual([
        "assets/app.js",
        "index.html",
      ]);
      expect(first.fileCount).toBe(2);
      expect(first.totalBytes).toBeGreaterThan(0);

      writeFileSync(join(root, "assets", "app.js"), "export const changed = true;\n");
      expect(directoryTreeManifest(root).treeSha256).not.toBe(first.treeSha256);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects symbolic links in an invocation-owned build", () => {
    const root = fixtureRoot();
    try {
      writeFileSync(join(root, "index.html"), "ready\n");
      symlinkSync("index.html", join(root, "linked-index.html"));
      expect(() => directoryTreeManifest(root)).toThrow("non-regular");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("source manifest covers tracked and untracked non-ignored files", () => {
    const root = fixtureRoot();
    try {
      execFileSync("git", ["init", "-q"], { cwd: root });
      writeFileSync(join(root, ".gitignore"), "ignored.txt\n");
      writeFileSync(join(root, "tracked.txt"), "tracked\n");
      writeFileSync(join(root, "untracked.txt"), "untracked\n");
      writeFileSync(join(root, "ignored.txt"), "ignored\n");
      execFileSync("git", ["add", ".gitignore", "tracked.txt"], { cwd: root });
      const manifest = sourceTreeManifest(root);
      expect(manifest.files.map(({ path }) => path)).toEqual([
        ".gitignore",
        "tracked.txt",
        "untracked.txt",
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects source symlinks instead of hashing only mutable link text", () => {
    const root = fixtureRoot();
    try {
      execFileSync("git", ["init", "-q"], { cwd: root });
      writeFileSync(join(root, "target.ts"), "export const value = 1;\n");
      symlinkSync("target.ts", join(root, "source.ts"));
      execFileSync("git", ["add", "source.ts", "target.ts"], { cwd: root });
      expect(() => sourceTreeManifest(root)).toThrow(
        "accepts only regular files",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects ignored source symlinks before Vite can dereference them", () => {
    const root = fixtureRoot();
    try {
      execFileSync("git", ["init", "-q"], { cwd: root });
      writeFileSync(join(root, ".gitignore"), "ignored-source.ts\n");
      writeFileSync(join(root, "entry.ts"), "import './ignored-source';\n");
      writeFileSync(join(root, "target.ts"), "export const value = 1;\n");
      symlinkSync("target.ts", join(root, "ignored-source.ts"));
      execFileSync("git", ["add", ".gitignore", "entry.ts", "target.ts"], {
        cwd: root,
      });
      expect(() => sourceTreeManifest(root)).toThrow(
        "accepts only regular files",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("managed performance Vite config ignores an ambient production env sentinel", async () => {
    const root = fixtureRoot();
    const previousPerformanceBuild =
      process.env.TI_SCALE_PERFORMANCE_BUILD;
    try {
      writeFileSync(join(root, "index.html"), "<main>fixture</main>\n");
      writeFileSync(
        join(root, ".env.production"),
        "VITE_TI_SCALE_PERFORMANCE_SENTINEL=must-not-load\n",
      );
      process.env.TI_SCALE_PERFORMANCE_BUILD = "true";
      const config = await resolveConfig({
        root,
        configFile: resolve(import.meta.dir, "../../..", "vite.config.ts"),
        mode: "production",
        logLevel: "silent",
      }, "build");
      expect(config.envDir).toBe(false);
      expect(config.env.VITE_TI_SCALE_PERFORMANCE_SENTINEL).toBeUndefined();
      expect(JSON.stringify(config.env)).not.toContain("must-not-load");
    } finally {
      if (previousPerformanceBuild === undefined) {
        delete process.env.TI_SCALE_PERFORMANCE_BUILD;
      } else {
        process.env.TI_SCALE_PERFORMANCE_BUILD = previousPerformanceBuild;
      }
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("classifies every same-origin static resource from the build manifest", () => {
    const root = fixtureRoot();
    try {
      const paths = [
        "assets/app.js",
        "brand-v2/optimized/hero.webp",
        "Logo.svg",
        "fonts/interface.woff2",
        "manifest.webmanifest",
        "sw-v2.js",
      ];
      for (const path of paths) {
        mkdirSync(join(root, path, ".."), { recursive: true });
        writeFileSync(join(root, path), `bytes:${path}\n`);
      }
      const build = directoryTreeManifest(root);
      expect(
        classifyObservedResourceUrl(
          "/assets/app.js",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "static-build", path: "assets/app.js" });
      expect(
        classifyObservedResourceUrl(
          "/brand-v2/optimized/hero.webp?rev=1",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toEqual({
        kind: "static-build",
        requestUrl:
          "http://127.0.0.1:43880/brand-v2/optimized/hero.webp?rev=1",
        path: "brand-v2/optimized/hero.webp",
      });
      for (const path of paths.slice(2)) {
        expect(
          classifyObservedResourceUrl(
            `/${path}`,
            "http://127.0.0.1:43880/",
            build,
          ),
        ).toMatchObject({ kind: "static-build", path });
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("records dynamic, external, and non-network exclusions explicitly", () => {
    const root = fixtureRoot();
    try {
      writeFileSync(join(root, "index.html"), "ready\n");
      const build = directoryTreeManifest(root);
      expect(
        classifyObservedResourceUrl(
          "/api/v2/health?detail=1",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "dynamic-api" });
      expect(
        classifyObservedResourceUrl(
          "/api/v2/events",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "dynamic-api" });
      expect(
        classifyObservedResourceUrl(
          "/api/v2evil",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "unclassified-same-origin" });
      expect(
        classifyObservedResourceUrl(
          "https://cdn.example.test/interface.woff2",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "external-origin" });
      expect(observedResourceIntegrityFailure(
        classifyObservedResourceUrl(
          "https://cdn.example.test/interface.woff2",
          "http://127.0.0.1:43880/",
          build,
        ),
      )).toContain("Unpinned external HTTP(S) resource");
      expect(observedResourceIntegrityFailure(
        classifyObservedResourceUrl(
          "/api/v2/health",
          "http://127.0.0.1:43880/",
          build,
        ),
      )).toBeUndefined();
      expect(
        classifyObservedResourceUrl(
          "data:image/svg+xml;base64,PHN2Zy8+",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "non-http" });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects and redacts embedded URL credentials before recording evidence", () => {
    const root = fixtureRoot();
    try {
      mkdirSync(join(root, "assets"));
      writeFileSync(join(root, "assets", "app.js"), "export {};\n");
      const classification = classifyObservedResourceUrl(
        "http://operator:super-secret@127.0.0.1:43880/assets/app.js",
        "http://127.0.0.1:43880/",
        directoryTreeManifest(root),
      );
      expect(classification).toMatchObject({
        kind: "invalid",
        requestUrl: "http://127.0.0.1:43880/assets/app.js",
      });
      expect(JSON.stringify(classification)).not.toContain("operator");
      expect(JSON.stringify(classification)).not.toContain("super-secret");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("never records a malformed credential-bearing URL verbatim", () => {
    const root = fixtureRoot();
    try {
      writeFileSync(join(root, "index.html"), "ready\n");
      const raw =
        "http://operator:super-secret@[invalid/assets/app.js?token=also-secret";
      const classification = classifyObservedResourceUrl(
        raw,
        "http://127.0.0.1:43880/",
        directoryTreeManifest(root),
      );
      expect(classification).toMatchObject({
        kind: "invalid",
        reason:
          "the observed resource URL is malformed and was replaced by a content-free digest",
      });
      expect(classification.requestUrl).toMatch(
        /^malformed-url:sha256:[a-f0-9]{64}$/u,
      );
      expect(classification.requestUrl).not.toContain("operator");
      expect(classification.requestUrl).not.toContain("super-secret");
      expect(classification.requestUrl).not.toContain("also-secret");
      expect(JSON.stringify(classification)).not.toContain(raw);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("fails closed for unknown, malformed, and traversing same-origin URLs", () => {
    const root = fixtureRoot();
    try {
      writeFileSync(join(root, "index.html"), "ready\n");
      const build = directoryTreeManifest(root);
      expect(
        classifyObservedResourceUrl(
          "/brand-v2/missing.webp",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "unclassified-same-origin" });
      expect(
        classifyObservedResourceUrl(
          "/assets/%ZZ/app.js",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "invalid" });
      expect(
        classifyObservedResourceUrl(
          "/assets/%2e%2e/index.html",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "invalid" });
      expect(
        classifyObservedResourceUrl(
          "/assets/%252e%252e/index.html",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "invalid" });
      expect(
        classifyObservedResourceUrl(
          "http://[invalid",
          "http://127.0.0.1:43880/",
          build,
        ),
      ).toMatchObject({ kind: "invalid" });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("detects observed static response bytes that differ from the build", () => {
    const root = fixtureRoot();
    try {
      writeFileSync(join(root, "index.html"), "ready\n");
      const build = directoryTreeManifest(root);
      const file = build.files[0]!;
      expect(staticResponseIntegrityFailures(build, [{
        path: file.path,
        bytes: file.bytes,
        sha256: file.sha256,
      }])).toEqual([]);
      expect(staticResponseIntegrityFailures(build, [{
        path: file.path,
        bytes: file.bytes,
        sha256: "0".repeat(64),
      }])).toEqual([
        "Observed bytes differ from the invocation-owned build: index.html",
      ]);
      expect(staticResponseIntegrityFailures(build, [{
        path: "missing.svg",
        bytes: 1,
        sha256: "0".repeat(64),
      }])).toEqual([
        "Observed path is absent from the complete build manifest: missing.svg",
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("publishes evidence atomically with no-overwrite semantics", () => {
    const root = fixtureRoot();
    try {
      const output = join(root, "results", "receipt.json");
      publishAtomicTextExclusive(output, "{\"status\":\"pass\"}\n");
      expect(readFileSync(output, "utf8")).toBe("{\"status\":\"pass\"}\n");
      expect(() =>
        publishAtomicTextExclusive(output, "{\"status\":\"replacement\"}\n"))
        .toThrow();
      expect(readFileSync(output, "utf8")).toBe("{\"status\":\"pass\"}\n");
      expect(
        readdirSync(join(root, "results")).filter((name) => name.endsWith(".tmp")),
      ).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("reserves one immutable run evidence directory and rejects run ID reuse", () => {
    const root = fixtureRoot();
    try {
      const evidenceRoot = performanceEvidenceRunDirectory(root, "unit-run");
      reserveImmutableEvidenceDirectory(evidenceRoot);
      const receipt = join(evidenceRoot, "receipt.json");
      publishAtomicTextExclusive(receipt, "{\"original\":true}\n");
      expect(() => reserveImmutableEvidenceDirectory(evidenceRoot)).toThrow();
      expect(readFileSync(receipt, "utf8")).toBe("{\"original\":true}\n");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("uses one immutable build baseline to detect cross-environment drift", () => {
    const root = fixtureRoot();
    try {
      const buildRoot = join(root, "build");
      const evidenceRoot = join(root, "evidence");
      mkdirSync(buildRoot);
      mkdirSync(evidenceRoot);
      writeFileSync(join(buildRoot, "index.html"), "build-a\n");
      const buildA = directoryTreeManifest(buildRoot);
      const path = performanceBuildBaselinePath(evidenceRoot);
      publishAtomicTextExclusive(path, `${JSON.stringify({
        schemaVersion: PERFORMANCE_BUILD_PROVENANCE_SCHEMA,
        runId: "shared-build-unit",
        measuredAt: "2026-07-26T00:00:00.000Z",
        build: summarizeFileTree(buildA),
        releaseCandidateEligible: false,
      })}\n`);
      const baseline = readPerformanceBuildBaseline(
        path,
        "shared-build-unit",
      );
      expect(sameFileTreeSummary(
        baseline.build,
        summarizeFileTree(buildA),
      )).toBe(true);

      writeFileSync(join(buildRoot, "index.html"), "build-b\n");
      const buildB = directoryTreeManifest(buildRoot);
      expect(sameFileTreeSummary(
        baseline.build,
        summarizeFileTree(buildB),
      )).toBe(false);
      expect(() => publishAtomicTextExclusive(path, "{}\n")).toThrow();
      expect(readPerformanceBuildBaseline(path, "shared-build-unit"))
        .toEqual(baseline);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("validates an invocation-bound source baseline", () => {
    const root = fixtureRoot();
    try {
      writeFileSync(join(root, "index.html"), "ready\n");
      const runId = "performance-unit-run";
      const path = performanceSourceBaselinePath(root, runId);
      const baseline = {
        schemaVersion: PERFORMANCE_SOURCE_PROVENANCE_SCHEMA,
        runId,
        measuredAt: "2026-07-26T00:00:00.000Z",
        source: summarizeFileTree(directoryTreeManifest(root)),
        launcher: {
          runtime: "bun",
          version: "1.3.14",
        },
      } as const;
      publishAtomicTextExclusive(path, `${JSON.stringify(baseline)}\n`);
      expect(readPerformanceSourceBaseline(path, runId)).toEqual(baseline);
      expect(() => readPerformanceSourceBaseline(path, "another-run")).toThrow(
        "malformed or mismatched",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
