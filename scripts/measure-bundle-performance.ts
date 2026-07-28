import { gzipSync } from "node:zlib";
import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { basename, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const distRoot = resolve(root, "dist");
const assetsRoot = resolve(distRoot, "assets");
const initialJavaScriptBudgetBytes = 250_000;
const routeJavaScriptBudgetBytes = 150_000;

if (!existsSync(resolve(distRoot, "index.html"))) {
  throw new Error("Build output is missing. Run `bun run build` before measuring.");
}

const indexHtml = readFileSync(resolve(distRoot, "index.html"), "utf8");
const initialAssetPaths = [
  ...indexHtml.matchAll(
    /<(?:script|link)\b[^>]*(?:src|href)="([^"]+)"[^>]*>/gu,
  ),
]
  .map((match) => match[1]!)
  .filter((path) => path.startsWith("/assets/"));
const initialJavaScript = new Set(
  initialAssetPaths
    .filter((path) => path.endsWith(".js"))
    .map((path) => basename(path)),
);

interface MeasuredAsset {
  readonly file: string;
  readonly rawBytes: number;
  readonly gzipBytes: number;
  readonly initial: boolean;
}

const measured = readdirSync(assetsRoot)
  .filter((file) => file.endsWith(".js"))
  .map((file): MeasuredAsset => {
    const path = resolve(assetsRoot, file);
    const bytes = readFileSync(path);
    return {
      file,
      rawBytes: statSync(path).size,
      gzipBytes: gzipSync(bytes, { level: 9 }).byteLength,
      initial: initialJavaScript.has(file),
    };
  })
  .sort((left, right) => right.gzipBytes - left.gzipBytes);

const initialJavaScriptGzipBytes = measured
  .filter(({ initial }) => initial)
  .reduce((total, asset) => total + asset.gzipBytes, 0);
const oversizedRouteChunks = measured.filter(
  ({ initial, gzipBytes }) => !initial && gzipBytes > routeJavaScriptBudgetBytes,
);
const failures = [
  ...(initialJavaScriptGzipBytes > initialJavaScriptBudgetBytes
    ? [
        `Initial JavaScript is ${initialJavaScriptGzipBytes} bytes gzip; budget is ${initialJavaScriptBudgetBytes}.`,
      ]
    : []),
  ...oversizedRouteChunks.map(
    ({ file, gzipBytes }) =>
      `${file} is ${gzipBytes} bytes gzip; route budget is ${routeJavaScriptBudgetBytes}.`,
  ),
];

console.log(
  JSON.stringify(
    {
      schemaVersion: "ti-scale.bundle-performance.v1",
      measuredAt: new Date().toISOString(),
      budgets: {
        initialJavaScriptGzipBytes: initialJavaScriptBudgetBytes,
        routeJavaScriptGzipBytes: routeJavaScriptBudgetBytes,
      },
      result: failures.length === 0 ? "pass" : "fail",
      initialJavaScriptGzipBytes,
      initialAssets: measured.filter(({ initial }) => initial),
      largestRouteChunks: measured.filter(({ initial }) => !initial).slice(0, 10),
      failures,
    },
    null,
    2,
  ),
);

if (failures.length > 0) process.exitCode = 1;
