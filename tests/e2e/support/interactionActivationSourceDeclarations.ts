import { relative, resolve, sep } from "node:path";

const AUTONOMOUS_INTAKE_HELPERS = Object.freeze([
  "tests/e2e/support/autonomousIntake.ts",
  "tests/e2e/support/titaniumSelect.ts",
] as const);

/**
 * Explicit source declarations for tests whose physical activation behavior
 * is delegated to shared helpers. Exact paths keep this auditable: a new spec
 * cannot silently inherit a broad filename-pattern exemption.
 */
const HELPER_SOURCES_BY_TEST = new Map<string, readonly string[]>([
  ["tests/e2e/autonomous-intake-context.spec.ts", AUTONOMOUS_INTAKE_HELPERS],
  ["tests/e2e/autonomous-intake-agent-model-assignments.spec.ts", AUTONOMOUS_INTAKE_HELPERS],
  ["tests/e2e/autonomous-intake-contract-normalization.spec.ts", AUTONOMOUS_INTAKE_HELPERS],
  ["tests/e2e/autonomous-intake-launch.spec.ts", AUTONOMOUS_INTAKE_HELPERS],
  ["tests/e2e/autonomous-intake-readiness.spec.ts", AUTONOMOUS_INTAKE_HELPERS],
  ["tests/e2e/autonomous-intake-scope-outcome-navigation.spec.ts", AUTONOMOUS_INTAKE_HELPERS],
  ["tests/e2e/autonomous-intake-team-readiness.spec.ts", AUTONOMOUS_INTAKE_HELPERS],
]);

export function declaredInteractionActivationHelperSources(input: {
  readonly sourceRoot: string;
  readonly testSourceFile: string;
}): readonly string[] {
  const root = resolve(input.sourceRoot);
  const testSource = resolve(input.testSourceFile);
  const relativePath = relative(root, testSource).split(sep).join("/");
  return HELPER_SOURCES_BY_TEST.get(relativePath) ?? [];
}

export function interactionActivationSourceDeclarations(): ReadonlyMap<string, readonly string[]> {
  return HELPER_SOURCES_BY_TEST;
}
