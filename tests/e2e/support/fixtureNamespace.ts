import { createHash } from "node:crypto";
import type { TestInfo } from "@playwright/test";

const MAX_NAMESPACE_LENGTH = 64;

function sanitize(value: string): string {
  return value
    .normalize("NFKC")
    .toLocaleLowerCase("en-US")
    .replaceAll(/[^a-z0-9]+/gu, "-")
    .replaceAll(/^-+|-+$/gu, "");
}

export function normalizeFixtureNamespace(value: string): string {
  const candidate = sanitize(value);
  if (!candidate) throw new Error("Fixture namespace must contain at least one ASCII letter or number");
  if (candidate.length <= MAX_NAMESPACE_LENGTH) return candidate;
  const digest = createHash("sha256").update(candidate, "utf8").digest("hex").slice(0, 12);
  return `${candidate.slice(0, MAX_NAMESPACE_LENGTH - digest.length - 1).replaceAll(/-+$/gu, "")}-${digest}`;
}

/**
 * Produces a stable, SQL/URL-safe namespace for canonical E2E records.
 *
 * Playwright projects intentionally share one isolated V2 database during a
 * matrix run. Project and worker identity therefore belong in every
 * deterministic fixture key; the digest preserves uniqueness when readable
 * names exceed the bounded identifier length.
 */
export function canonicalFixtureNamespace(
  testInfo: Pick<TestInfo, "project" | "workerIndex">,
  testInstance: string,
): string {
  const project = sanitize(testInfo.project.name) || "unnamed-project";
  const instance = sanitize(testInstance) || "unnamed-test";
  return normalizeFixtureNamespace(`${project}-${instance}-worker-${testInfo.workerIndex}`);
}
