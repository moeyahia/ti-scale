import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { StartupDatabaseIntegrityVerifier } from "../StartupDatabaseIntegrityVerifier";

const SLOW_CHILD = fileURLToPath(new URL(
  "./fixtures/SlowStartupDatabaseIntegrityChild.ts",
  import.meta.url,
));

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function disposableDatabase(): { readonly root: string; readonly path: string } {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-startup-integrity-"));
  const path = join(root, "ti-scale.sqlite");
  const database = createDatabaseConnection({ filename: path, verifyIntegrity: false });
  try { migrateDatabase(database); }
  finally { database.close(); }
  return { root, path };
}

describe("StartupDatabaseIntegrityVerifier", () => {
  test("returns one receipt for the exact unchanged database while timers continue on the parent event loop", async () => {
    const fixture = disposableDatabase();
    try {
      const verifier = new StartupDatabaseIntegrityVerifier({ timeoutMs: 30_000 });
      let heartbeats = 0;
      const timer = setInterval(() => { heartbeats += 1; }, 1);
      try {
        const result = await verifier.verify(fixture.path);
        expect(result).toEqual({ ok: true, messages: ["ok"] });
        expect(heartbeats).toBeGreaterThan(0);
      } finally {
        clearInterval(timer);
        await verifier.stop();
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  }, 35_000);

  test("shutdown terminates and drains an in-flight integrity child", async () => {
    const fixture = disposableDatabase();
    try {
      const verifier = new StartupDatabaseIntegrityVerifier({
        timeoutMs: 30_000,
        childEntrypoint: SLOW_CHILD,
      });
      const verification = verifier.verify(fixture.path);
      await delay(50);
      await verifier.stop();
      await expect(verification).rejects.toThrow("cancelled");
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  }, 5_000);
});
