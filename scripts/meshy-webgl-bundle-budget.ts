import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import type { OutputAsset, OutputChunk } from "rollup";
import type { Plugin } from "vite";

const MESHY_WEBGL_GZIP_BUDGETS = Object.freeze({
  MeshyWebglPage: 15 * 1024,
  MeshyWebglRuntime: 150 * 1024,
  AssemblyReviewPage: 24 * 1024,
  AssemblyReviewRuntime: 150 * 1024,
  ParticleCoreReviewPage: 24 * 1024,
  ParticleCoreRuntime: 150 * 1024,
  GLTFLoader: 20 * 1024,
  meshopt_decoder: 10 * 1024,
});

const ACTIVE_WEBGL_CHUNKS = Object.freeze([
  "ParticleCoreReviewPage",
  "ParticleCoreRuntime",
  "GLTFLoader",
] as const);

const APPROVED_MESHY_CHUNKS = Object.freeze([
  "MeshyWebglPage",
  "MeshyWebglRuntime",
  "meshopt_decoder",
] as const);

const ASSEMBLY_REVIEW_ROOT = "review-assets/ti-scale-14-elements/v1";

function filesBelow(root: string): string[] {
  if (!existsSync(root)) return [];
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(root, entry.name);
    return entry.isDirectory() ? filesBelow(path) : entry.isFile() ? [path] : [];
  });
}

function approvedDeliveryViolations(publicRoot: string): string[] {
  const optimizedRoot = resolve(publicRoot, "brand-v2/optimized/meshy-webgl");
  const manifestPath = resolve(publicRoot, "brand-v2/source/meshy-webgl/approved-webgl-manifest.json");
  const models = filesBelow(optimizedRoot).filter((path) => path.toLowerCase().endsWith(".glb"));
  if (models.length === 0 && !existsSync(manifestPath)) return [];
  if (models.length !== 1 || !existsSync(manifestPath)) {
    return ["An approved WebGL delivery must have exactly one optimized GLB and one approval manifest."];
  }
  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  } catch {
    return ["The approved WebGL manifest is not valid JSON."];
  }
  const approval = manifest.approval as Record<string, unknown> | undefined;
  const model = manifest.model as Record<string, unknown> | undefined;
  const modelPath = relative(publicRoot, models[0]!).replaceAll("\\", "/");
  const bytes = statSync(models[0]!).size;
  const digest = createHash("sha256").update(readFileSync(models[0]!)).digest("hex");
  const violations: string[] = [];
  if (manifest.status !== "operator-approved" || approval?.approvedBy !== "operator") {
    violations.push("The public WebGL model does not have an operator approval state.");
  }
  if (typeof approval?.receiptId !== "string" || !/^approval_[a-z0-9][a-z0-9_-]{7,127}$/u.test(approval.receiptId)) {
    violations.push("The public WebGL model does not have a valid approval receipt ID.");
  }
  if (model?.path !== modelPath || model?.bytes !== bytes || model?.sha256 !== digest) {
    violations.push("The public WebGL model bytes, path, or SHA-256 do not match the approval manifest.");
  }
  if (!modelPath.toLowerCase().includes(digest.slice(0, 12))) {
    violations.push("The public WebGL model filename is not content-addressed.");
  }
  return violations;
}

function reviewDeliveryViolations(publicRoot: string): string[] {
  const reviewRoot = resolve(publicRoot, ASSEMBLY_REVIEW_ROOT);
  const modelRoot = resolve(reviewRoot, "models");
  const manifestPath = resolve(reviewRoot, "assembly-manifest.json");
  const models = filesBelow(modelRoot).filter((path) => path.toLowerCase().endsWith(".glb"));
  if (models.length === 0 && !existsSync(manifestPath)) return [];
  if (models.length !== 14 || !existsSync(manifestPath)) {
    return ["The review-only assembly delivery must have exactly 14 content-addressed GLBs and one review manifest."];
  }
  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  } catch {
    return ["The review-only assembly manifest is not valid JSON."];
  }
  const entries = Array.isArray(manifest.models) ? manifest.models as Array<Record<string, unknown>> : [];
  const fasteners = Array.isArray(manifest.fasteners) ? manifest.fasteners : [];
  const violations: string[] = [];
  if (manifest.status !== "review-candidate" || manifest.reviewBoundary !== "Review candidate — not approved for hero") {
    violations.push("The assembly delivery must remain an explicitly unapproved review candidate.");
  }
  if (entries.length !== 14 || fasteners.length !== 26) {
    violations.push("The assembly review manifest must declare exactly 14 models and 26 runtime fasteners.");
  }
  const declaredPaths = new Set<string>();
  for (const entry of entries) {
    const path = typeof entry.path === "string" ? entry.path : "";
    const absolute = resolve(publicRoot, path);
    const digest = existsSync(absolute) ? createHash("sha256").update(readFileSync(absolute)).digest("hex") : "";
    const bytes = existsSync(absolute) ? statSync(absolute).size : -1;
    declaredPaths.add(absolute);
    if (!absolute.startsWith(`${modelRoot}/`) || !path.endsWith(".glb")) {
      violations.push(`Review model path escapes its isolated asset root: ${path || "[missing]"}.`);
    } else if (entry.sha256 !== digest || entry.bytes !== bytes) {
      violations.push(`Review model bytes or SHA-256 do not match the manifest: ${path}.`);
    } else if (!path.includes(digest.slice(0, 12))) {
      violations.push(`Review model filename is not content-addressed: ${path}.`);
    }
  }
  for (const model of models) {
    if (!declaredPaths.has(model)) violations.push(`Undeclared GLB exists in the review asset root: ${relative(publicRoot, model)}.`);
  }
  return violations;
}

function matchingBudget(chunk: OutputChunk): { readonly label: string; readonly bytes: number } | undefined {
  for (const [label, bytes] of Object.entries(MESHY_WEBGL_GZIP_BUDGETS)) {
    if (chunk.name.startsWith(label)) return { label, bytes };
  }
  return undefined;
}

/** Fail the production build if the asset-gated WebGL chunks exceed their explicit gzip budgets. */
export function meshyWebglBundleBudget(): Plugin {
  let approvedMeshyDeliveryPresent = false;
  return {
    name: "ti-scale-meshy-webgl-bundle-budget",
    apply: "build",
    enforce: "post",
    buildStart() {
      const publicRoot = resolve(process.cwd(), "public");
      approvedMeshyDeliveryPresent =
        filesBelow(resolve(publicRoot, "brand-v2/optimized/meshy-webgl"))
          .some((path) => path.toLowerCase().endsWith(".glb"))
        || existsSync(resolve(publicRoot, "brand-v2/source/meshy-webgl/approved-webgl-manifest.json"));
      const candidateRoot = resolve(publicRoot, "brand-v2/source/meshy-3d");
      const reviewRoot = resolve(publicRoot, ASSEMBLY_REVIEW_ROOT);
      const candidateFiles = filesBelow(candidateRoot);
      const unapprovedGlbs = filesBelow(publicRoot).filter((path) => (
        /\.(?:glb|gltf)$/u.test(path.toLowerCase())
        && !path.startsWith(`${resolve(publicRoot, "brand-v2/optimized/meshy-webgl")}/`)
        && !path.startsWith(`${reviewRoot}/`)
      ));
      const forbidden = [...new Set([...candidateFiles, ...unapprovedGlbs])];
      const approvalViolations = approvedDeliveryViolations(publicRoot);
      const reviewViolations = reviewDeliveryViolations(publicRoot);
      if (forbidden.length > 0 || approvalViolations.length > 0 || reviewViolations.length > 0) {
        throw new Error([
          "Unapproved Meshy candidate files are inside Vite's public directory and would be bundled.",
          "Only the operator-approved hero delivery or the explicit hash-verified 14-element review delivery may be public.",
          ...forbidden.map((path) => `- ${relative(process.cwd(), path)}`),
          ...approvalViolations.map((violation) => `- ${violation}`),
          ...reviewViolations.map((violation) => `- ${violation}`),
        ].join("\n"));
      }
    },
    generateBundle(_options, bundle: Record<string, OutputAsset | OutputChunk>) {
      const observed = new Set<string>();
      for (const output of Object.values(bundle)) {
        if (output.type !== "chunk") continue;
        const budget = matchingBudget(output);
        if (!budget) continue;
        observed.add(budget.label);
        const compressedBytes = gzipSync(output.code, { level: 9 }).byteLength;
        if (compressedBytes > budget.bytes) {
          throw new Error(`${budget.label} is ${compressedBytes} gzip bytes; its WebGL budget is ${budget.bytes}.`);
        }
      }
      const requiredChunks = approvedMeshyDeliveryPresent
        ? [...ACTIVE_WEBGL_CHUNKS, ...APPROVED_MESHY_CHUNKS]
        : ACTIVE_WEBGL_CHUNKS;
      for (const required of requiredChunks) {
        if (!observed.has(required)) throw new Error(`The required deferred WebGL chunk ${required} was not emitted.`);
      }
    },
  };
}
