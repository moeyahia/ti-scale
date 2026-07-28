import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const SERVER_ROOT = resolve(import.meta.dir, "../..");
const RUNTIME_ROOTS = [
  "command-runtime",
  "autonomous-runtime",
  "guided-commander",
  "run-intelligence",
  "intelligence-v24",
  "specialist-runtime",
] as const;

const AGENT_CONTROL_ROOTS = [
  "command-runtime",
  "guided-commander",
  "run-intelligence",
  "intelligence-v24",
  "specialist-runtime",
] as const;

const AUTONOMOUS_AGENT_CONTROL_FILES = [
  "autonomous-runtime/LocalAutonomousContractPlanner.ts",
  "autonomous-runtime/LocalVerifiedEvidenceOutcomeEvaluator.ts",
  "autonomous-runtime/AutonomousDnsSpecialistAdapter.ts",
] as const;

function productionTypescriptFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      return entry.name === "__tests__" || entry.name === "testing"
        ? []
        : productionTypescriptFiles(path);
    }
    return entry.isFile() && entry.name.endsWith(".ts") ? [path] : [];
  });
}

describe("agent Second Brain entrypoint boundary", () => {
  test("keeps runtime and agent surfaces away from direct Vault and raw Context Pack retrieval", () => {
    const files = RUNTIME_ROOTS.flatMap((root) => productionTypescriptFiles(join(SERVER_ROOT, root)));
    const violations = files.flatMap((path) => {
      const source = readFileSync(path, "utf8");
      const reasons = [
        ...(source.includes("retrieveAndPersistContext(") ? ["raw Context Pack retrieval"] : []),
        ...(source.includes("ObsidianVaultBridge") ? ["direct Obsidian Vault access"] : []),
      ];
      return reasons.map((reason) => `${relative(SERVER_ROOT, path)}: ${reason}`);
    });
    expect(violations).toEqual([]);
  });

  test("keeps commander and specialist control surfaces away from direct filesystem access", () => {
    const files = [
      ...AGENT_CONTROL_ROOTS.flatMap((root) =>
        productionTypescriptFiles(join(SERVER_ROOT, root))),
      ...AUTONOMOUS_AGENT_CONTROL_FILES.map((path) => join(SERVER_ROOT, path)),
    ];
    const violations = files.flatMap((path) => {
      const source = readFileSync(path, "utf8");
      const reasons = [
        ...(
          source.includes('from "node:fs')
          || source.includes("from 'node:fs")
          || /\b(?:from|require\s*\()\s*["']fs(?:\/promises)?["']/u.test(source)
          ? ["direct filesystem import"]
          : []),
        ...(/\b(?:Bun\.(?:file|write)|Deno\.(?:open|readFile|readTextFile|writeFile|writeTextFile))\s*\(/u
          .test(source)
          ? ["direct filesystem operation"]
          : []),
        ...(/\bfrom\s*["'][^"']*\/vault(?:\/[^"']*)?["']/u.test(source)
          ? ["direct Vault module import"]
          : []),
      ];
      return reasons.map((reason) => `${relative(SERVER_ROOT, path)}: ${reason}`);
    });
    expect(violations).toEqual([]);
  });

  test("keeps every public commander or specialist lifecycle seam bound to BrainContextService", () => {
    const entrypoints = [
      "missions/MissionService.ts",
      "command-runtime/MissionRuntimeEngine.ts",
      "guided-commander/GuidedCommanderService.ts",
      "guided-commander/LocalGuidedCommander.ts",
      "guided-commander/LocalGuidedManualInterpreter.ts",
      "run-intelligence/AttackAttemptService.ts",
      "intelligence-v24/OperationalTruthService.ts",
      "plan-changes/PlanChangeRouter.ts",
      "routes/operationsRoutes.ts",
    ] as const;
    const missing = entrypoints.filter((relativePath) => {
      const source = readFileSync(join(SERVER_ROOT, relativePath), "utf8");
      return !/\bBrainContextService\b|\bretrieveMissionBrainContext\b/u.test(source);
    });
    expect(missing).toEqual([]);
  });
});
