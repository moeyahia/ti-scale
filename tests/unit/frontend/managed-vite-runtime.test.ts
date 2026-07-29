import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const managedViteLauncher = readFileSync(
  new URL("../../../scripts/start-managed-e2e-vite-server.ts", import.meta.url),
  "utf8",
);

describe("managed Vite runtime", () => {
  test("runs Vite on Node so closed browser event streams release upstream subscriptions", () => {
    expect(managedViteLauncher).toContain('const node = Bun.which("node")');
    expect(managedViteLauncher).toContain(
      "Node is required to run the managed Vite development server",
    );
    expect(managedViteLauncher).toMatch(
      /const child = Bun\.spawn\(\[\s*node,\s*viteEntry,/u,
    );
    expect(managedViteLauncher).not.toMatch(
      /const child = Bun\.spawn\(\[\s*process\.execPath,\s*viteEntry,/u,
    );
  });

  test("reports and fails an unexpected managed Vite exit", () => {
    expect(managedViteLauncher).toContain('"managed-vite-unexpected-exit"');
    expect(managedViteLauncher).toContain(
      "process.exitCode = forwardedSignal ? exitCode : exitCode || 1",
    );
  });
});
