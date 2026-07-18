import { mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  createFileManifest,
  writeAttestationAtomically,
  type ReleaseAttestation,
} from "../../../scripts/release-attestation";

describe("immutable release attestation primitives", () => {
  test("creates a deterministic, sorted manifest and records symlink identity without following it", () => {
    const root = mkdtempSync(resolve(tmpdir(), "ti-scale-attestation-"));
    mkdirSync(resolve(root, "nested"));
    writeFileSync(resolve(root, "z.txt"), "last");
    writeFileSync(resolve(root, "nested/a.txt"), "first");
    symlinkSync("nested/a.txt", resolve(root, "link.txt"));

    const first = createFileManifest(root);
    const second = createFileManifest(root);
    expect(first).toEqual(second);
    expect(first.entries.map((entry) => entry.path)).toEqual(["link.txt", "nested/a.txt", "z.txt"]);
    expect(first.entries[0]).toMatchObject({ kind: "symlink", linkTarget: "nested/a.txt" });
    expect(first.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  test("excludes build, dependency, database, and test-result roots from the source manifest", () => {
    const root = mkdtempSync(resolve(tmpdir(), "ti-scale-attestation-source-"));
    for (const directory of ["src", "dist", "node_modules", "test-results", "data", "artifacts"]) {
      mkdirSync(resolve(root, directory));
      writeFileSync(resolve(root, directory, "entry.txt"), directory);
    }
    writeFileSync(resolve(root, ".env.example"), "DOCUMENTED=true");
    writeFileSync(resolve(root, ".env.local"), "SECRET=do-not-hash");
    writeFileSync(resolve(root, "local.sqlite"), "not-a-real-database");
    writeFileSync(resolve(root, "runtime.log"), "ephemeral");
    const manifest = createFileManifest(root, { excludeSourceEphemera: true });
    expect(manifest.entries.map((entry) => entry.path)).toEqual([".env.example", "src/entry.txt"]);
  });

  test("writes a private, complete receipt atomically", () => {
    const root = mkdtempSync(resolve(tmpdir(), "ti-scale-attestation-write-"));
    const output = resolve(root, "nested/receipt.json");
    const receipt = {
      schemaVersion: "ti-scale.release-attestation.v1",
      immutableSourceAttested: false,
      releaseCandidateEligible: false,
      signed: false,
      blockers: ["test blocker"],
    } as unknown as ReleaseAttestation;
    writeAttestationAtomically(output, receipt);
    expect(JSON.parse(readFileSync(output, "utf8"))).toEqual(receipt);
  });
});
