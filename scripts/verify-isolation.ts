import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

const root = resolve(import.meta.dir, "..");
const productionRootNames = ["src", "server", "scripts", "shared"] as const;
const productionRoots = productionRootNames.map((name) => resolve(root, name)).filter(existsSync);
const self = resolve(import.meta.path);
const productionExtensions = /\.(?:cjs|css|js|mjs|ts|tsx)$/u;
const forbiddenImports = [
  /(?:from\s*|import\s*\()\s*["'][^"']*(?:chillspwn\/plugin\/webapp|webapp\/src)(?:\/|["'])/u,
  /(?:from\s*|import\s*\()\s*["'][^"']*pages\/(?:ChatPage|AgentCockpitPage|MissionBoardPage)(?:\.[^"']+)?["']/u,
  /(?:from\s*|import\s*\()\s*["'][^"']*LegacyDesktop(?:\.[^"']+)?["']/u,
  /(?:from\s*|import\s*\()\s*["'][^"']*webapp\/src\/index\.css["']/u,
];
const importSpecifier = /(?:from\s*|import\s*\()\s*["']([^"']+)["']/gu;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = resolve(dir, name);
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) throw new Error(`Ti-Scale production source contains a symbolic link: ${relative(root, path)}`);
    return metadata.isDirectory() ? files(path) : metadata.isFile() ? [path] : [];
  });
}

const violations: string[] = [];
const scannedFiles = productionRoots.flatMap(files)
  .filter((entry) => productionExtensions.test(entry) && entry !== self);
for (const path of scannedFiles) {
  const text = readFileSync(path, "utf8");
  for (const pattern of forbiddenImports) {
    if (pattern.test(text)) violations.push(`${relative(root, path)} imports a protected legacy UI boundary`);
  }
  for (const match of text.matchAll(importSpecifier)) {
    const specifier = match[1]!;
    if (!specifier.startsWith(".")) continue;
    const imported = resolve(dirname(path), specifier);
    const fromRoot = relative(root, imported);
    if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
      violations.push(`${relative(root, path)} imports outside the standalone repository: ${specifier}`);
    }
  }
}

const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
  readonly name?: unknown;
  readonly dependencies?: Readonly<Record<string, unknown>>;
  readonly devDependencies?: Readonly<Record<string, unknown>>;
};
if (packageJson.name !== "@ti-scale/platform") violations.push("package.json must retain the standalone @ti-scale/platform identity");
for (const [name, version] of Object.entries({
  ...packageJson.dependencies,
  ...packageJson.devDependencies,
})) {
  if (typeof version === "string" && /^(?:file|link|workspace):/u.test(version)) {
    violations.push(`package dependency ${name} crosses the standalone package boundary through ${version}`);
  }
}

const viteConfig = readFileSync(resolve(root, "vite.config.ts"), "utf8");
for (const required of [
  /envPrefix:\s*"VITE_TI_SCALE_"/u,
  /outDir:\s*"dist"/u,
  /port:\s*43140/u,
  /"\/api\/v2"/u,
]) {
  if (!required.test(viteConfig)) violations.push(`vite.config.ts is missing standalone boundary ${required}`);
}
if (/envPrefix:[^\n]*["']TI_SCALE_["']/u.test(viteConfig)) {
  violations.push(
    "vite.config.ts exposes server-owned TI_SCALE_* configuration to browser modules",
  );
}

const browserNamespaces = readFileSync(resolve(root, "src/lib/browserNamespaces.ts"), "utf8");
if (!/TI_SCALE_BROWSER_NAMESPACE\s*=\s*"ti-scale"/u.test(browserNamespaces)) {
  violations.push("browser namespaces do not use the ti-scale root");
}
if (/chillspwn|command-os-v2/iu.test(browserNamespaces)) {
  violations.push("browser namespace definitions contain a legacy namespace");
}

if (violations.length) throw new Error(`Ti-Scale isolation check failed:\n${violations.join("\n")}`);
console.log(`Ti-Scale standalone source boundary verified across ${String(scannedFiles.length)} production files`);
