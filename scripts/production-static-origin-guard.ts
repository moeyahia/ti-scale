import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import type { OutputAsset, OutputChunk } from "rollup";
import type { Plugin, ResolvedConfig } from "vite";

export const FORBIDDEN_PRODUCTION_API_ORIGINS = Object.freeze([
  "http://127.0.0.1:43141",
  "http://localhost:43141",
] as const);

export interface ProductionArtifactContent {
  readonly fileName: string;
  readonly content: string | Uint8Array;
}

const ABSOLUTE_API_V2_REFERENCE =
  /(?:https?:)?\/\/[a-z0-9.[\]:_-]+(?::\d{1,5})?\/api\/v2(?:[/?#]|\\u002f|\\\/|$)/giu;
const BUILD_TIME_API_ORIGIN_TOKEN = /VITE_TI_SCALE_API_ORIGIN/gu;

function contains(value: string | Uint8Array, needle: string): boolean {
  return typeof value === "string"
    ? value.includes(needle)
    : Buffer.from(value).includes(Buffer.from(needle));
}

function text(value: string | Uint8Array): string {
  return typeof value === "string" ? value : Buffer.from(value).toString("utf8");
}

async function collectArtifactDirectory(
  root: string,
  current = root,
): Promise<ProductionArtifactContent[]> {
  const artifacts: ProductionArtifactContent[] = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    if (entry.isDirectory()) {
      artifacts.push(...await collectArtifactDirectory(root, path));
      continue;
    }
    if (!entry.isFile()) continue;
    artifacts.push({
      fileName: path.slice(resolve(root).length + 1),
      content: await readFile(path),
    });
  }
  return artifacts;
}

/**
 * Production browser code is served by the API process and must retain
 * same-origin `/api/v2/...` requests. The 43141 origin belongs exclusively to
 * the split development API server and must never become a release artifact.
 */
export function assertProductionStaticOrigins(
  artifacts: readonly ProductionArtifactContent[],
): void {
  const violations = artifacts.flatMap((artifact) => (
    FORBIDDEN_PRODUCTION_API_ORIGINS
      .filter((origin) => contains(artifact.content, origin))
      .map((origin) => `${artifact.fileName}: ${origin}`)
  ));
  for (const artifact of artifacts) {
    const content = text(artifact.content);
    for (const match of content.matchAll(ABSOLUTE_API_V2_REFERENCE)) {
      violations.push(`${artifact.fileName}: absolute API reference ${match[0]}`);
    }
    if (BUILD_TIME_API_ORIGIN_TOKEN.test(content)) {
      violations.push(`${artifact.fileName}: build-time API origin token`);
    }
    BUILD_TIME_API_ORIGIN_TOKEN.lastIndex = 0;
  }
  if (violations.length > 0) {
    throw new Error([
      "Production static artifacts contain an absolute or build-time API origin.",
      "Keep browser requests relative so either tunnel endpoint remains same-origin with Ti-Scale on port 3132.",
      ...violations.map((violation) => `- ${violation}`),
    ].join("\n"));
  }
}

/** Fail a production build before its output can be staged as a static release. */
export function productionStaticOriginGuard(): Plugin {
  let resolvedConfig: ResolvedConfig | undefined;
  return {
    name: "ti-scale-production-static-origin-guard",
    apply: "build",
    enforce: "post",
    configResolved(config) {
      resolvedConfig = config;
    },
    generateBundle(_options, bundle: Record<string, OutputAsset | OutputChunk>) {
      assertProductionStaticOrigins(Object.values(bundle).map((output) => ({
        fileName: output.fileName,
        content: output.type === "chunk" ? output.code : output.source,
      })));
    },
    async closeBundle() {
      if (!resolvedConfig) throw new Error("Production static origin guard did not receive the resolved Vite config.");
      const outDir = resolve(resolvedConfig.root, resolvedConfig.build.outDir);
      assertProductionStaticOrigins(await collectArtifactDirectory(outDir));
    },
  };
}
