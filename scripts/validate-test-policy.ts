import {
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import {
  relative,
  resolve,
  sep,
} from "node:path";
import ts from "typescript";

const repositoryRoot = resolve(import.meta.dir, "..");
const ignoredDirectoryNames = new Set([
  ".git",
  "coverage",
  "dist",
  "node_modules",
  "playwright-report",
  "test-results",
]);
const testFilePattern = /\.(?:test|spec)\.(?:ts|tsx)$/u;

const unitSuiteRoots = [
  "tests/unit",
  "server",
  "src/lib",
  "scripts/release/__tests__",
] as const;
const browserSuiteRoot = "tests/e2e";

function normalizedRelativePath(path: string): string {
  return relative(repositoryRoot, path).split(sep).join("/");
}

function walk(path: string, files: string[]): void {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectoryNames.has(entry.name)) continue;
    const child = resolve(path, entry.name);
    if (entry.isDirectory()) {
      walk(child, files);
    } else if (entry.isFile() && testFilePattern.test(entry.name)) {
      files.push(child);
    }
  }
}

function isWithin(relativePath: string, root: string): boolean {
  return relativePath === root || relativePath.startsWith(`${root}/`);
}

function calledName(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) return expression.text;
  if (!ts.isPropertyAccessExpression(expression)) return undefined;
  const parent = calledName(expression.expression);
  return parent ? `${parent}.${expression.name.text}` : expression.name.text;
}

export function findForbiddenModifiers(path: string): readonly string[] {
  const sourceText = readFileSync(path, "utf8");
  const source = ts.createSourceFile(
    path,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    path.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  const violations: string[] = [];
  const forbiddenTerminalNames = new Set([
    "fail",
    "failing",
    "fixme",
    "only",
    "skip",
    "todo",
  ]);
  const forbiddenAliases = new Set([
    "fdescribe",
    "fit",
    "xdescribe",
    "xit",
    "xtest",
  ]);

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = calledName(node.expression);
      const segments = name?.split(".") ?? [];
      const terminal = segments.at(-1);
      if (
        (name && forbiddenAliases.has(name))
        || (
          terminal
          && forbiddenTerminalNames.has(terminal)
          && segments.length > 1
        )
      ) {
        const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
        violations.push(`${normalizedRelativePath(path)}:${String(line)} calls ${name}`);
      }

      const configuresRetry = node.arguments.some((argument) =>
        ts.isObjectLiteralExpression(argument)
        && argument.properties.some((property) =>
          ts.isPropertyAssignment(property)
          && /^retries?$/u.test(property.name.getText(source))
          && property.initializer.getText(source) !== "0"));
      if (
        name
        && (
          /^(?:describe|it|test)(?:\.each)?$/u.test(name)
          || /^(?:describe|it|test)(?:\.describe)?\.configure$/u.test(name)
        )
        && configuresRetry
      ) {
        const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
        violations.push(
          `${normalizedRelativePath(path)}:${String(line)} configures a non-zero test retry`,
        );
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return Object.freeze(violations);
}

export interface TestPolicyResult {
  readonly testFiles: number;
  readonly unitFiles: number;
  readonly browserFiles: number;
}

export function validateTestPolicy(): TestPolicyResult {
  const files: string[] = [];
  walk(repositoryRoot, files);
  const violations: string[] = [];
  let unitFiles = 0;
  let browserFiles = 0;

  for (const path of files.sort()) {
    const relativePath = normalizedRelativePath(path);
    const isUnit = unitSuiteRoots.some((root) => isWithin(relativePath, root));
    const isBrowser = isWithin(relativePath, browserSuiteRoot);
    if (isUnit === isBrowser) {
      violations.push(
        `${relativePath} must belong to exactly one audited unit/module or browser suite`,
      );
    } else if (isUnit) {
      unitFiles += 1;
    } else {
      browserFiles += 1;
    }
    violations.push(...findForbiddenModifiers(path));
  }

  if (files.length === 0) violations.push("No test files were discovered");
  if (violations.length > 0) {
    throw new Error(`Test policy validation failed:\n- ${violations.join("\n- ")}`);
  }
  return Object.freeze({
    testFiles: files.length,
    unitFiles,
    browserFiles,
  });
}

if (import.meta.main) {
  const result = validateTestPolicy();
  console.log(
    `Test policy verified: ${String(result.testFiles)} files; `
      + `${String(result.unitFiles)} unit/module and ${String(result.browserFiles)} browser; `
      + "zero skipped, focused, todo, expected-failure, or retry-masked declarations",
  );
}
