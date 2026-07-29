import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "../../..");
const workflowPath = resolve(root, ".github/workflows/playwright-release.yml");
const uploadArtifactAction =
  "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02";
const expectedPaths = [
  "playwright-report/",
  "test-results/html/",
  "test-results/results/",
  "test-results/playwright/",
  "tests/interaction-manifest.json",
  "tests/interaction-manifest.schema.json",
  "tests/interaction-manifest/visual-baselines.json",
  "tests/accessibility-state-inventory.json",
] as const;

type Mapping = Readonly<Record<string, unknown>>;

function mapping(value: unknown, label: string): Mapping {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a mapping`);
  }
  return value as Mapping;
}

function sequence(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be a sequence`);
  return value;
}

describe("Playwright release evidence retention policy", () => {
  test("uploads only reviewed browser evidence before unconditional cleanup", () => {
    const workflow = mapping(
      Bun.YAML.parse(readFileSync(workflowPath, "utf8")),
      "workflow",
    );
    const jobs = mapping(workflow.jobs, "jobs");
    const job = mapping(jobs["full-browser-gate"], "full-browser-gate");
    const steps = sequence(job.steps, "steps").map((value, index) =>
      mapping(value, `step ${String(index + 1)}`));
    const uploadIndex = steps.findIndex((step) =>
      step.uses === uploadArtifactAction);
    const cleanupIndex = steps.findIndex((step) =>
      step.if === "always()"
      && typeof step.run === "string"
      && step.run.includes("rm -rf"));

    expect(uploadIndex).toBeGreaterThan(-1);
    expect(cleanupIndex).toBeGreaterThan(uploadIndex);

    const upload = steps[uploadIndex]!;
    expect(upload.if).toBe("always()");
    const options = mapping(upload.with, "upload options");
    expect(options.name).toBe(
      "ti-scale-playwright-release-${{ github.run_id }}-${{ github.run_attempt }}",
    );
    expect(
      String(options.path).split(/\r?\n/u).map((value) => value.trim()).filter(Boolean),
    ).toEqual([...expectedPaths]);
    expect(options["if-no-files-found"]).toBe("warn");
    expect(options["include-hidden-files"]).toBe(false);
    expect(options["retention-days"]).toBe(14);
    expect(options.overwrite).toBe(false);
  });

  test("does not retain disposable credentials, databases, Vaults, or live configuration", () => {
    const workflow = readFileSync(workflowPath, "utf8");
    const uploadBlock = workflow.slice(
      workflow.indexOf("- name: Upload sanitized browser release evidence"),
      workflow.indexOf("- name: Remove transient runner output"),
    );

    expect(uploadBlock).not.toContain("/tmp/");
    expect(uploadBlock).not.toContain("ti-scale-e2e-data");
    expect(uploadBlock).not.toContain("auth-state");
    expect(uploadBlock).not.toContain("operator-token");
    expect(uploadBlock).not.toContain("research-integrity-key");
    expect(uploadBlock).not.toContain(".sqlite");
    expect(uploadBlock).not.toContain("vaults-");
    expect(uploadBlock).not.toContain("provider-config");
    expect(uploadBlock).not.toContain("script-sources");
    expect(uploadBlock).not.toContain(".env");
  });
});
