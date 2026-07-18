import { readdirSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import ts from "typescript";

export const V2_MUTATION_METHODS = ["POST", "PUT", "PATCH", "DELETE"] as const;
export type V2MutationMethod = (typeof V2_MUTATION_METHODS)[number];

export interface DiscoveredV2MutationRoute {
  readonly method: V2MutationMethod;
  readonly path: string;
  readonly source: string;
  readonly line: number;
}

interface DiscoveryFailure {
  readonly source: string;
  readonly line: number;
  readonly expression: string;
}

export interface V2MutationRouteDiscovery {
  readonly routes: readonly DiscoveredV2MutationRoute[];
  readonly unresolved: readonly DiscoveryFailure[];
}

type Environment = ReadonlyMap<string, string>;

function sourceFiles(root: string): string[] {
  const result: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "__tests__") visit(path);
      } else if (entry.isFile() && entry.name.endsWith(".ts")) {
        result.push(path);
      }
    }
  };
  visit(root);
  return result.sort();
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isAsExpression(current)
    || ts.isTypeAssertionExpression(current)
    || ts.isParenthesizedExpression(current)
    || ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function stringValue(expression: ts.Expression, environment: Environment): string | undefined {
  const value = unwrap(expression);
  if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) return value.text;
  if (ts.isIdentifier(value)) {
    return environment.get(value.text);
  }
  if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = stringValue(value.left, environment);
    const right = stringValue(value.right, environment);
    return left === undefined || right === undefined ? undefined : `${left}${right}`;
  }
  if (ts.isTemplateExpression(value)) {
    let result = value.head.text;
    for (const span of value.templateSpans) {
      const interpolation = stringValue(span.expression, environment);
      if (interpolation === undefined) return undefined;
      result += interpolation + span.literal.text;
    }
    return result;
  }
  return undefined;
}

function stringArray(expression: ts.Expression, environment: Environment): readonly string[] | undefined {
  const value = unwrap(expression);
  if (!ts.isArrayLiteralExpression(value)) return undefined;
  const values = value.elements.map((element) => stringValue(element as ts.Expression, environment));
  return values.every((item): item is string => item !== undefined) ? values : undefined;
}

function normalizedPath(value: string): string {
  const path = value.trim().replace(/\/{2,}/gu, "/");
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

function declaredPrefixDefault(sourceFile: ts.SourceFile): string {
  const candidates = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken
      && (ts.isStringLiteral(node.right) || ts.isNoSubstitutionTemplateLiteral(node.right))
      && node.right.text.startsWith("/api/v2")
    ) {
      candidates.add(normalizedPath(node.right.text));
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  if (candidates.size > 1) {
    throw new Error(`Router source declares ambiguous V2 base paths: ${[...candidates].join(", ")}`);
  }
  return [...candidates][0] ?? "/api/v2";
}

/**
 * Statically discovers Express mutation declarations without importing a router
 * or opening its database. The evaluator is deliberately narrow: an
 * unevaluable /api/v2 mutation declaration is a CI failure rather than an
 * invitation to silently omit it from the authority inventory.
 */
export function discoverV2MutationRoutes(
  workspaceRoot = resolve(import.meta.dir, "../.."),
): V2MutationRouteDiscovery {
  const serverRoot = resolve(workspaceRoot, "server");
  const routes: DiscoveredV2MutationRoute[] = [];
  const unresolved: DiscoveryFailure[] = [];

  for (const filename of sourceFiles(serverRoot)) {
    const sourceText = readFileSync(filename, "utf8");
    const sourceFile = ts.createSourceFile(filename, sourceText, ts.ScriptTarget.Latest, true);
    const source = relative(workspaceRoot, filename).replaceAll("\\", "/");

    const visit = (node: ts.Node, environment: Environment): void => {
      if (ts.isForOfStatement(node) && ts.isVariableDeclarationList(node.initializer)) {
        const declaration = node.initializer.declarations[0];
        const values = stringArray(node.expression, environment);
        if (declaration && ts.isIdentifier(declaration.name) && values) {
          for (const value of values) {
            const nested = new Map(environment);
            nested.set(declaration.name.text, value);
            visit(node.statement, nested);
          }
          return;
        }
      }

      if (
        ts.isCallExpression(node)
        && ts.isPropertyAccessExpression(node.expression)
        && ["post", "put", "patch", "delete"].includes(node.expression.name.text)
        && node.arguments[0]
      ) {
        const routePath = stringValue(node.arguments[0], environment);
        const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
        const receiver = node.expression.expression;
        const routeReceiver = ts.isIdentifier(receiver)
          && ["router", "app", "web"].includes(receiver.text);
        if (routePath?.startsWith("/api/v2")) {
          routes.push({
            method: node.expression.name.text.toUpperCase() as V2MutationMethod,
            path: normalizedPath(routePath),
            source,
            line,
          });
        } else if (routeReceiver || node.arguments[0].getText(sourceFile).includes("api/v2")) {
          unresolved.push({
            source,
            line,
            expression: node.arguments[0].getText(sourceFile),
          });
        }
      }
      ts.forEachChild(node, (child) => visit(child, environment));
    };

    const initialEnvironment = new Map<string, string>();
    initialEnvironment.set("prefix", declaredPrefixDefault(sourceFile));
    visit(sourceFile, initialEnvironment);
  }

  return {
    routes: routes.sort((left, right) =>
      left.path.localeCompare(right.path) || left.method.localeCompare(right.method) || left.source.localeCompare(right.source)),
    unresolved,
  };
}
