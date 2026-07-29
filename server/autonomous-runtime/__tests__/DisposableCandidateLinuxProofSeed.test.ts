import {
  mkdtempSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  migrateDatabase,
} from "../../db";
import {
  DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED,
  seedDisposableCandidateLinuxProof,
} from "../DisposableCandidateLinuxProofSeed";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("seedDisposableCandidateLinuxProof", () => {
  test("creates one canonical fixture-only spec and is idempotent", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-proof-seed-"));
    roots.push(root);
    const databasePath = join(root, "ti-scale-proof.sqlite");
    const sourceRoot = join(root, "ti-scale-script-sources");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS);
      const first = seedDisposableCandidateLinuxProof({
        database,
        databasePath,
        scriptSourceRoot: sourceRoot,
        now: () => new Date("2026-07-23T16:00:00.000Z"),
      });
      const second = seedDisposableCandidateLinuxProof({
        database,
        databasePath,
        scriptSourceRoot: sourceRoot,
        now: () => new Date("2026-07-23T17:00:00.000Z"),
      });
      expect(first).toMatchObject({
        status: "created",
        fixtureOnly: true,
        realTargetSupport: false,
        postExploitSpecId:
          DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED.postExploitSpecId,
      });
      expect(second).toEqual({ ...first, status: "already_current" });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM candidate_linux_post_exploit_specs
        WHERE id = ?
      `).get(
        DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED.postExploitSpecId,
      )).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT scope_json, status FROM missions WHERE id = ?
      `).get(DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED.missionId)).toEqual({
        scope_json: "{\"fixtureOnly\":true,\"realTargetSupport\":false}",
        status: "archived",
      });
    } finally {
      database.close();
    }
  });
});
