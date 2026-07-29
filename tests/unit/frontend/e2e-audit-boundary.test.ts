import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import ts from "typescript";
import {
  e2eAuditProfile,
  eventStreamLifecyclePairCausallyMatchesRequest,
} from "../../e2e/support/browserAudit";

const E2E_ROOT = resolve(import.meta.dir, "../../e2e");
const EXPECTED_BROWSER_SPECIFICATIONS = [
  "accessibility-axe.spec.ts",
  "agent-model-settings-real-backend.spec.ts",
  "agent-model-settings.spec.ts",
  "artifact-delivery.spec.ts",
  "artifact-intelligence.spec.ts",
  "attack-knowledge-promotion.spec.ts",
  "auth-session.spec.ts",
  "autonomous-activation-receipt.spec.ts",
  "autonomous-branch-contract.spec.ts",
  "autonomous-intake-agent-model-assignments.spec.ts",
  "autonomous-intake-context.spec.ts",
  "autonomous-intake-contract-normalization.spec.ts",
  "autonomous-intake-launch.spec.ts",
  "autonomous-intake-readiness.spec.ts",
  "autonomous-intake-scope-outcome-navigation.spec.ts",
  "autonomous-intake-team-readiness.spec.ts",
  "autonomous-planning-selection.spec.ts",
  "boot-sequence.spec.ts",
  "brain-control.spec.ts",
  "brain-graph.spec.ts",
  "brain-home-inbox.spec.ts",
  "brain-node-lifecycle.spec.ts",
  "brain-node-vault.spec.ts",
  "brain-operational-hazard.spec.ts",
  "brain-read-retry-accessibility.spec.ts",
  "brain-readiness-isolation.spec.ts",
  "brain-source-custody.spec.ts",
  "brain-vault-attack-preset.spec.ts",
  "brain-vault-disconnect.spec.ts",
  "brain-vault-navigation.spec.ts",
  "brain-vault.spec.ts",
  "browser-audit-canary.spec.ts",
  "command-palette-autonomous-search.spec.ts",
  "command-palette.spec.ts",
  "cve-applicability.spec.ts",
  "decisions-intelligence.spec.ts",
  "direct-plan-editor.spec.ts",
  "dynamic-technical-disclosures.spec.ts",
  "early-auth-startup.spec.ts",
  "failure-diagnosis.spec.ts",
  "guided-provider-free-capabilities.spec.ts",
  "interaction-manifest.spec.ts",
  "light-technology-theme.spec.ts",
  "live-autonomous-3132.spec.ts",
  "live-readonly-3132.spec.ts",
  "manifest-coverage-audit.spec.ts",
  "mechanical-assembly.spec.ts",
  "mechanical-route-transition.spec.ts",
  "meshy-webgl.spec.ts",
  "mission-intake.spec.ts",
  "mission-portfolio.spec.ts",
  "model-candidate-review.spec.ts",
  "motion-lab-assembly.spec.ts",
  "motion-lab.spec.ts",
  "namespace-isolation.spec.ts",
  "openrouter-connection.spec.ts",
  "operational-lists.spec.ts",
  "operational-truth.spec.ts",
  "operator-preferences.spec.ts",
  "overview-journey-readiness.spec.ts",
  "overview-particle-core.spec.ts",
  "particle-core-review.spec.ts",
  "particle-module-transition.spec.ts",
  "performance-web-vitals.spec.ts",
  "plan-changes.spec.ts",
  "report-generation.spec.ts",
  "research-lab.spec.ts",
  "route-smoke.spec.ts",
  "run-intervention-recovery.spec.ts",
  "run-metrics.spec.ts",
  "run-model-assignments.spec.ts",
  "static-csp.spec.ts",
  "system.spec.ts",
  "titanium-chassis.spec.ts",
  "zoom-accessibility.spec.ts",
] as const;

function specificationPaths(root = E2E_ROOT): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) return specificationPaths(path);
    return entry.isFile() && entry.name.endsWith(".spec.ts") ? [path] : [];
  });
}

function specifications(): Array<{
  readonly name: string;
  readonly path: string;
  readonly source: string;
  readonly sourceFile: ts.SourceFile;
}> {
  return specificationPaths().sort().map((path) => {
    const source = readFileSync(path, "utf8");
    return {
      name: path.slice(E2E_ROOT.length + 1),
      path,
      source,
      sourceFile: ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS),
    };
  });
}

function importedNames(node: ts.ImportDeclaration): Array<{ readonly imported: string; readonly local: string }> {
  const bindings = node.importClause?.namedBindings;
  if (!bindings || !ts.isNamedImports(bindings)) return [];
  return bindings.elements.map((element) => ({
    imported: element.propertyName?.text ?? element.name.text,
    local: element.name.text,
  }));
}

function calledProperty(node: ts.CallExpression): { readonly receiver: string; readonly property: string } | undefined {
  if (ts.isPropertyAccessExpression(node.expression)) {
    return { receiver: node.expression.expression.getText(), property: node.expression.name.text };
  }
  if (ts.isElementAccessExpression(node.expression) && node.expression.argumentExpression && ts.isStringLiteral(node.expression.argumentExpression)) {
    return { receiver: node.expression.expression.getText(), property: node.expression.argumentExpression.text };
  }
  return undefined;
}

function isWithinNavigationTeardownBoundary(node: ts.Node): boolean {
  for (let current: ts.Node | undefined = node.parent; current; current = current.parent) {
    if (!ts.isCallExpression(current)) continue;
    const call = calledProperty(current);
    if (call?.property === "withExpectedDocumentNavigationTeardown") return true;
  }
  return false;
}

function isWithinHistoryTraversalBoundary(node: ts.Node): boolean {
  for (let current: ts.Node | undefined = node.parent; current; current = current.parent) {
    if (!ts.isCallExpression(current)) continue;
    const call = calledProperty(current);
    if (call?.property === "withExpectedHistoryTraversal") return true;
  }
  return false;
}

type AuditCapability = "page" | "context" | "api-request" | "audit" | "browser";

function bindingIdentifiers(name: ts.BindingName): ts.Identifier[] {
  if (ts.isIdentifier(name)) return [name];
  return name.elements.flatMap((element) => ts.isOmittedExpression(element) ? [] : bindingIdentifiers(element.name));
}

function propertyCallNode(node: ts.CallExpression): { readonly receiver: ts.Expression; readonly property: string } | undefined {
  if (ts.isPropertyAccessExpression(node.expression)) {
    return { receiver: node.expression.expression, property: node.expression.name.text };
  }
  if (
    ts.isElementAccessExpression(node.expression)
    && node.expression.argumentExpression
    && ts.isStringLiteral(node.expression.argumentExpression)
  ) return { receiver: node.expression.expression, property: node.expression.argumentExpression.text };
  return undefined;
}

function auditBoundaryViolations(name: string, sourceFile: ts.SourceFile): string[] {
  const httpMethods = new Set(["fetch", "get", "post", "put", "patch", "delete", "head"]);
  const forbiddenLifecycle = new Set(["finalize", "dispose", "attach", "closeAuditedPage"]);
  const capabilities = new Map<string, AuditCapability>();
  const callableAliases = new Map<string, string>();
  const helperParameters = new Map<string, ts.ParameterDeclaration[]>();
  const issues: string[] = [];
  const line = (node: ts.Node) => sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  const capabilityFromName = (identifier: string): AuditCapability | undefined => {
    if (identifier === "page") return "page";
    if (identifier === "context") return "context";
    if (identifier === "request") return "api-request";
    if (identifier === "browser") return "browser";
    if (/^(?:browserAudit|audit|session|lifecycle)$/u.test(identifier)) return "audit";
    return undefined;
  };
  const setCapability = (identifier: string, capability: AuditCapability | undefined): boolean => {
    if (!capability || capabilities.get(identifier) === capability) return false;
    capabilities.set(identifier, capability);
    return true;
  };
  const expressionCapability = (expression: ts.Expression): AuditCapability | undefined => {
    if (ts.isParenthesizedExpression(expression)) return expressionCapability(expression.expression);
    if (ts.isIdentifier(expression)) return capabilities.get(expression.text) ?? capabilityFromName(expression.text);
    if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
      const receiver = expression.expression;
      const property = ts.isPropertyAccessExpression(expression)
        ? expression.name.text
        : expression.argumentExpression && ts.isStringLiteral(expression.argumentExpression)
          ? expression.argumentExpression.text
          : undefined;
      const base = expressionCapability(receiver);
      if (base === "page" && property === "request") return "api-request";
    }
    return undefined;
  };
  const forbiddenAliasDescription = (expression: ts.Expression): string | undefined => {
    if (!ts.isPropertyAccessExpression(expression) && !ts.isElementAccessExpression(expression)) return undefined;
    const receiver = expression.expression;
    const property = ts.isPropertyAccessExpression(expression)
      ? expression.name.text
      : expression.argumentExpression && ts.isStringLiteral(expression.argumentExpression)
        ? expression.argumentExpression.text
        : undefined;
    if (!property) return undefined;
    const capability = expressionCapability(receiver);
    if (capability === "api-request" && httpMethods.has(property)) return `direct audited-API bypass alias .${property}`;
    if (capability === "browser" && property === "newContext") return "unaudited context-creation alias";
    if (capability === "audit" && forbiddenLifecycle.has(property)) return `audit lifecycle alias .${property}`;
    if ((capability === "page" || capability === "context") && property === "close") return `${capability} close alias`;
    if (capability === "page" && property === "reload") return "page reload alias";
    return undefined;
  };

  const collect = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name) helperParameters.set(node.name.text, [...node.parameters]);
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)
      && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
      helperParameters.set(node.name.text, [...node.initializer.parameters]);
    }
    if (ts.isParameter(node)) {
      const typeName = node.type?.getText();
      for (const identifier of bindingIdentifiers(node.name)) {
        const capability = typeName === "Page" ? "page"
          : typeName === "BrowserContext" ? "context"
            : typeName === "APIRequestContext" ? "api-request"
              : capabilityFromName(identifier.text);
        setCapability(identifier.text, capability);
      }
      if (ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) {
          const property = element.propertyName?.getText() ?? element.name.getText();
          for (const identifier of bindingIdentifiers(element.name)) setCapability(identifier.text, capabilityFromName(property));
        }
      }
    }
    ts.forEachChild(node, collect);
  };
  collect(sourceFile);

  let changed = true;
  while (changed) {
    changed = false;
    const propagate = (node: ts.Node): void => {
      if (ts.isVariableDeclaration(node)) {
        if (node.initializer) {
          const capability = expressionCapability(node.initializer);
          for (const identifier of bindingIdentifiers(node.name)) changed = setCapability(identifier.text, capability) || changed;
          if (ts.isIdentifier(node.name)) {
            const alias = forbiddenAliasDescription(node.initializer);
            if (alias && callableAliases.get(node.name.text) !== alias) {
              callableAliases.set(node.name.text, alias);
              changed = true;
            }
          }
        }
        if (ts.isObjectBindingPattern(node.name) && node.initializer) {
          const base = expressionCapability(node.initializer);
          for (const element of node.name.elements) {
            const property = element.propertyName?.getText() ?? element.name.getText();
            for (const identifier of bindingIdentifiers(element.name)) {
              if (base === "page" && property === "request") changed = setCapability(identifier.text, "api-request") || changed;
              const synthetic = ts.factory.createPropertyAccessExpression(
                ts.factory.createIdentifier(base === "api-request" ? "request" : base ?? "unknown"),
                property,
              );
              const alias = forbiddenAliasDescription(synthetic);
              if (alias && callableAliases.get(identifier.text) !== alias) {
                callableAliases.set(identifier.text, alias);
                changed = true;
              }
            }
          }
        }
      }
      if (
        ts.isBinaryExpression(node)
        && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && ts.isIdentifier(node.left)
      ) {
        changed = setCapability(node.left.text, expressionCapability(node.right)) || changed;
        const alias = forbiddenAliasDescription(node.right);
        if (alias && callableAliases.get(node.left.text) !== alias) {
          callableAliases.set(node.left.text, alias);
          changed = true;
        }
      }
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
        const parameters = helperParameters.get(node.expression.text);
        if (parameters) parameters.forEach((parameter, index) => {
          const capability = node.arguments[index] ? expressionCapability(node.arguments[index]!) : undefined;
          for (const identifier of bindingIdentifiers(parameter.name)) changed = setCapability(identifier.text, capability) || changed;
        });
      }
      ts.forEachChild(node, propagate);
    };
    propagate(sourceFile);
  }

  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && node.text === "BrowserAuditSession") {
      issues.push(`${name}:${line(node)}: imports or references BrowserAuditSession`);
    }
    if (ts.isCallExpression(node)) {
      if (ts.isIdentifier(node.expression) && callableAliases.has(node.expression.text)) {
        issues.push(`${name}:${line(node)}: invokes ${callableAliases.get(node.expression.text)}`);
      }
      const call = propertyCallNode(node);
      if (call) {
        const capability = expressionCapability(call.receiver);
        if (capability === "api-request" && httpMethods.has(call.property)) {
          issues.push(`${name}:${line(node)}: direct audited API ${call.property} call through ${call.receiver.getText()}`);
        }
        if (capability === "browser" && call.property === "newContext") {
          issues.push(`${name}:${line(node)}: creates a second unaudited context`);
        }
        if (capability === "audit" && forbiddenLifecycle.has(call.property)) {
          issues.push(`${name}:${line(node)}: invokes audit lifecycle method ${call.property}`);
        }
        if ((capability === "page" || capability === "context") && call.property === "close") {
          issues.push(`${name}:${line(node)}: closes ${capability} outside the audit lifecycle`);
        }
        if (capability === "page" && call.property === "reload" && !isWithinNavigationTeardownBoundary(node)) {
          issues.push(`${name}:${line(node)}: reloads page without an exact navigation-teardown boundary`);
        }
        if (
          capability === "page"
          && (call.property === "goBack" || call.property === "goForward")
          && isWithinNavigationTeardownBoundary(node)
        ) {
          issues.push(`${name}:${line(node)}: history traversal incorrectly borrows a document-navigation teardown boundary`);
        }
        if (
          capability === "page"
          && call.property === "reload"
          && isWithinHistoryTraversalBoundary(node)
        ) {
          issues.push(`${name}:${line(node)}: document reload incorrectly borrows a history-traversal boundary`);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return issues;
}

describe("automatic E2E browser-audit boundary", () => {
  test("every browser specification imports the audited Playwright fixture", () => {
    const discovered = specifications();
    const auditedFixture = resolve(E2E_ROOT, "support/playwright");
    const violations = discovered.flatMap(({ name, path, sourceFile }) => {
      const issues: string[] = [];
      let auditedTestBinding = false;
      for (const statement of sourceFile.statements) {
        if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
        const moduleName = statement.moduleSpecifier.text;
        const names = importedNames(statement);
        if (moduleName === "@playwright/test") issues.push(`${name}: imports @playwright/test directly`);
        const resolvedModule = moduleName.startsWith(".") ? resolve(dirname(path), moduleName) : moduleName;
        for (const binding of names) {
          if (binding.imported !== "test") continue;
          if (resolvedModule === auditedFixture && binding.local === "test") auditedTestBinding = true;
          else issues.push(`${name}: test binding comes from ${moduleName} as ${binding.local}`);
        }
      }
      if (!auditedTestBinding) issues.push(`${name}: missing canonical audited test binding`);
      return issues;
    });
    expect(violations).toEqual([]);
    // An exact named inventory makes every added or removed browser spec an
    // intentional audit-boundary review. A numeric count could stay green when
    // one audited spec was deleted while an unrelated spec was added.
    expect(discovered.map(({ name }) => name)).toEqual([...EXPECTED_BROWSER_SPECIFICATIONS]);
  });

  test("browser specifications cannot bypass audited direct HTTP requests", () => {
    const violations = specifications().flatMap(({ name, sourceFile }) => auditBoundaryViolations(name, sourceFile));
    expect(violations).toEqual([]);
  });

  test("common aliases and helper wrappers cannot bypass the audit boundary", () => {
    const unsafeFixtures = [
      "const api = page.request; await api.get('/api/v2/escape');",
      "let api; api = page.request; await api.post('/api/v2/escape');",
      "const getOutsideAudit = page.request.get; await getOutsideAudit('/api/v2/escape');",
      "const { get: rawGet } = page.request; await rawGet('/api/v2/escape');",
      "async function requestHelper(client: unknown) { await client.get('/api/v2/escape'); } requestHelper(page.request);",
      "const makeContext = browser.newContext; await makeContext();",
      "const p = page; await p.close();",
      "const stopAudit = audit.finalize; await stopAudit(testInfo);",
      "const p = page; const bounce = p.reload; await bounce();",
      "async function reloadHelper(target: unknown) { await target.reload(); } await reloadHelper(page);",
      "history.pushState({}, '', '/brain/graph?selected=mem-one'); await audit.withExpectedDocumentNavigationTeardown(page, () => page.goBack());",
      "await audit.withExpectedDocumentNavigationTeardown(page, () => page.goForward());",
      "await audit.withExpectedHistoryTraversal(page, () => page.reload());",
    ];
    for (const [index, source] of unsafeFixtures.entries()) {
      const sourceFile = ts.createSourceFile(`negative-${index}.spec.ts`, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(auditBoundaryViolations(`negative-${index}.spec.ts`, sourceFile).length).toBeGreaterThan(0);
    }
    const safeSource = "await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload()); await audit.withExpectedHistoryTraversal(page, () => page.goBack()); await audit.request(request, { method: 'GET', url: '/api/v2/health' });";
    const safeFile = ts.createSourceFile("safe.spec.ts", safeSource, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    expect(auditBoundaryViolations("safe.spec.ts", safeFile)).toEqual([]);
  });

  test("permits only the controller-owned early page close used before a test dependency stops", () => {
    const sourceFile = ts.createSourceFile(
      "audited-dependency-shutdown.spec.ts",
      "await browserAudit.closePageBeforeDependencyShutdown(page);",
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    );
    expect(auditBoundaryViolations("audited-dependency-shutdown.spec.ts", sourceFile)).toEqual([]);
  });

  test("strict profiles are the default and relaxation requires explicit degraded mode", () => {
    expect(e2eAuditProfile({})).toBe("development");
    expect(e2eAuditProfile({ TI_SCALE_E2E_PROFILE: "development" })).toBe("development");
    expect(e2eAuditProfile({ TI_SCALE_E2E_PROFILE: "release", TI_SCALE_E2E_REQUIRE_API: "1" })).toBe("release");
    expect(e2eAuditProfile({ TI_SCALE_E2E_PROFILE: "degraded", TI_SCALE_E2E_REQUIRE_API: "0" })).toBe("degraded");
    expect(() => e2eAuditProfile({ TI_SCALE_E2E_PROFILE: "smoke" })).toThrow(
      "TI_SCALE_E2E_PROFILE must be development, release, or degraded",
    );
    expect(() => e2eAuditProfile({ TI_SCALE_E2E_PROFILE: "release", TI_SCALE_E2E_REQUIRE_API: "0" })).toThrow(
      "Required V2 API auditing can be relaxed only by the explicit degraded profile",
    );
  });

  test("binds an EventSource lifecycle pair only inside its exact document-to-close clock interval", () => {
    const exact = {
      receiptUrl: "http://127.0.0.1:43140/api/v2/events/stream?runId=one",
      receiptOrdinal: 1,
      documentStartedAt: 100,
      closedAt: 120,
      requestUrl: "http://127.0.0.1:43140/api/v2/events/stream?runId=one",
      requestOrdinal: 1,
      requestStartedAt: 110,
    } as const;
    expect(eventStreamLifecyclePairCausallyMatchesRequest(exact)).toBe(true);
    expect(eventStreamLifecyclePairCausallyMatchesRequest({ ...exact, requestStartedAt: 99 })).toBe(false);
    expect(eventStreamLifecyclePairCausallyMatchesRequest({ ...exact, requestStartedAt: 121 })).toBe(false);
    expect(eventStreamLifecyclePairCausallyMatchesRequest({ ...exact, requestOrdinal: 2 })).toBe(false);
    expect(eventStreamLifecyclePairCausallyMatchesRequest({
      ...exact,
      requestUrl: `${exact.requestUrl}&different=true`,
    })).toBe(false);
  });
});
