import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  RELEASE_GATE_IDS,
  buildReleaseAttestation,
  canonicalReleaseSignOffPayload,
  createFileManifest,
  readGitReceipt,
  writeAttestationAtomically,
  type ReleaseEvidenceBundle,
  type ReleaseSignOffPayload,
  type ReleaseAttestation,
} from "../../../scripts/release-attestation";

const digest = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

function applicationFixture(knownGaps: readonly string[] = []): { readonly root: string; readonly artifactRoot: string } {
  const root = mkdtempSync(resolve(tmpdir(), "ti-scale-release-candidate-"));
  mkdirSync(resolve(root, "public/brand-v2/source"), { recursive: true });
  mkdirSync(resolve(root, "server/db/migrations"), { recursive: true });
  mkdirSync(resolve(root, "src"));
  mkdirSync(resolve(root, "tests"));
  mkdirSync(resolve(root, "dist"));
  writeFileSync(resolve(root, ".gitignore"), "dist/\n");
  writeFileSync(resolve(root, "package.json"), "{}\n");
  writeFileSync(resolve(root, "bun.lock"), "fixture lock\n");
  writeFileSync(resolve(root, "public/brand-v2/source/ti-scale-mark.svg"), "<svg/>\n");
  writeFileSync(resolve(root, "public/brand-v2/source/ti-scale-wordmark.svg"), "<svg/>\n");
  writeFileSync(resolve(root, "server/db/migrations/001_initial.ts"), "export {};\n");
  writeFileSync(resolve(root, "src/index.ts"), "export const candidate = true;\n");
  writeFileSync(resolve(root, "tests/interaction-manifest.json"), `${JSON.stringify({ knownGaps }, null, 2)}\n`);
  writeFileSync(resolve(root, "dist/index.html"), "<!doctype html><title>Ti-Scale</title>\n");
  execFileSync("git", ["init", "--initial-branch=main"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Ti-Scale test"], { cwd: root });
  execFileSync("git", ["config", "user.email", "test@ti-scale.invalid"], { cwd: root });
  execFileSync("git", ["add", "."], { cwd: root });
  execFileSync("git", ["commit", "-m", "release fixture"], { cwd: root });
  return { root, artifactRoot: resolve(root, "dist") };
}

function signedEvidenceFixture(application: ReturnType<typeof applicationFixture>): {
  readonly evidencePath: string;
  readonly signOffPath: string;
  readonly trustedPublicKeyPath: string;
  readonly firstEvidenceArtifactPath: string;
} {
  const evidenceRoot = mkdtempSync(resolve(tmpdir(), "ti-scale-release-evidence-"));
  const source = createFileManifest(application.root, { excludeSourceEphemera: true });
  const artifact = createFileManifest(application.artifactRoot);
  const gitHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: application.root, encoding: "utf8" }).trim();
  const gates = RELEASE_GATE_IDS.map((gate, index) => {
    const path = `gate-${index + 1}.json`;
    const bytes = `${JSON.stringify({ gate, passed: true })}\n`;
    writeFileSync(resolve(evidenceRoot, path), bytes);
    return {
      gate,
      status: "passed" as const,
      completedAt: `2026-07-20T10:00:0${index}Z`,
      artifacts: [{ path, sha256: digest(bytes) }],
    };
  });
  const evidence = {
    schemaVersion: "ti-scale.release-evidence.v1",
    releaseId: "ti-scale-release-20260720",
    gitHead,
    sourceManifestSha256: source.sha256,
    artifactManifestSha256: artifact.sha256,
    knownGapCount: 0,
    openReleaseScopeDefectCount: 0,
    skippedTestCount: 0,
    quarantinedTestCount: 0,
    retryMaskedTestCount: 0,
    gates,
  } satisfies ReleaseEvidenceBundle;
  const evidencePath = resolve(evidenceRoot, "release-evidence.json");
  writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  const evidenceBundleSha256 = digest(readFileSync(evidencePath));
  const signOffPayload = {
    schemaVersion: "ti-scale.release-sign-off.v1",
    releaseId: evidence.releaseId,
    decision: "approved",
    approvedBy: "release-owner@example.test",
    approvedAt: "2026-07-20T11:00:00Z",
    gitHead,
    sourceManifestSha256: source.sha256,
    artifactManifestSha256: artifact.sha256,
    evidenceBundleSha256,
    signatureAlgorithm: "ed25519",
  } satisfies ReleaseSignOffPayload;
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signatureBase64 = cryptoSign(null, canonicalReleaseSignOffPayload(signOffPayload), privateKey).toString("base64");
  const trustedPublicKeyPath = resolve(evidenceRoot, "release-owner-public.pem");
  writeFileSync(trustedPublicKeyPath, publicKey.export({ type: "spki", format: "pem" }));
  const signOffPath = resolve(evidenceRoot, "release-sign-off.json");
  writeFileSync(signOffPath, `${JSON.stringify({ ...signOffPayload, signatureBase64 }, null, 2)}\n`);
  return {
    evidencePath,
    signOffPath,
    trustedPublicKeyPath,
    firstEvidenceArtifactPath: resolve(evidenceRoot, gates[0]!.artifacts[0]!.path),
  };
}

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
    for (const directory of ["src", "dist", "node_modules", "test-results", "data", "artifacts", ".artifacts"]) {
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

  test("reads a standalone repository root without passing an empty Git pathspec", async () => {
    const root = mkdtempSync(resolve(tmpdir(), "ti-scale-attestation-git-root-"));
    execFileSync("git", ["init", "--initial-branch=main"], { cwd: root });
    execFileSync("git", ["config", "user.name", "Ti-Scale test"], { cwd: root });
    execFileSync("git", ["config", "user.email", "test@ti-scale.invalid"], { cwd: root });
    writeFileSync(resolve(root, "package.json"), "{}\n");
    execFileSync("git", ["add", "package.json"], { cwd: root });
    execFileSync("git", ["commit", "-m", "fixture"], { cwd: root });

    const receipt = await readGitReceipt(root, root);
    expect(receipt.applicationPath).toBe(".");
    expect(receipt.applicationTracked).toBe(true);
    expect(receipt.applicationClean).toBe(true);

    writeFileSync(resolve(root, "untracked.txt"), "release gap\n");
    const dirtyReceipt = await readGitReceipt(root, root);
    expect(dirtyReceipt.applicationClean).toBe(false);
    expect(dirtyReceipt.changedPathCount).toBe(1);
  });

  test("remains unsigned and ineligible by default even for a clean immutable build", async () => {
    const application = applicationFixture();
    const receipt = await buildReleaseAttestation({
      repositoryRoot: application.root,
      applicationRoot: application.root,
      artifactRoot: application.artifactRoot,
      createdAt: "2026-07-20T12:00:00Z",
    });
    expect(receipt.immutableSourceAttested).toBe(true);
    expect(receipt.signed).toBe(false);
    expect(receipt.releaseCandidateEligible).toBe(false);
    expect(receipt.releaseEvidence.status).toBe("not-supplied");
    expect(receipt.humanSignOff.status).toBe("not-supplied");
    expect(receipt.blockers).toEqual([
      "No checksum-verified release-gate evidence bundle was supplied",
      "No cryptographically signed human release approval was supplied",
    ]);
  });

  test("becomes signed and eligible only from complete checksum-bound evidence and verified human approval", async () => {
    const application = applicationFixture();
    const approval = signedEvidenceFixture(application);
    const receipt = await buildReleaseAttestation({
      repositoryRoot: application.root,
      applicationRoot: application.root,
      artifactRoot: application.artifactRoot,
      createdAt: "2026-07-20T12:00:00Z",
      releaseEvidencePath: approval.evidencePath,
      humanSignOffPath: approval.signOffPath,
      trustedSignOffPublicKeyPath: approval.trustedPublicKeyPath,
    });
    expect(receipt.immutableSourceAttested).toBe(true);
    expect(receipt.releaseEvidence).toMatchObject({
      status: "validated",
      releaseId: "ti-scale-release-20260720",
      validatedGateCount: RELEASE_GATE_IDS.length,
    });
    expect(receipt.humanSignOff).toMatchObject({
      status: "verified",
      approvedBy: "release-owner@example.test",
      approvedAt: "2026-07-20T11:00:00Z",
    });
    expect(receipt.humanSignOff.trustedPublicKeySha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(receipt.signed).toBe(true);
    expect(receipt.releaseCandidateEligible).toBe(true);
    expect(receipt.blockers).toEqual([]);
  });

  test("does not treat a structurally valid but unverified approval as signed", async () => {
    const application = applicationFixture();
    const approval = signedEvidenceFixture(application);
    const signOff = JSON.parse(readFileSync(approval.signOffPath, "utf8")) as Record<string, unknown>;
    writeFileSync(approval.signOffPath, `${JSON.stringify({
      ...signOff,
      signatureBase64: Buffer.alloc(64).toString("base64"),
    }, null, 2)}\n`);
    const receipt = await buildReleaseAttestation({
      repositoryRoot: application.root,
      applicationRoot: application.root,
      artifactRoot: application.artifactRoot,
      createdAt: "2026-07-20T12:00:00Z",
      releaseEvidencePath: approval.evidencePath,
      humanSignOffPath: approval.signOffPath,
      trustedSignOffPublicKeyPath: approval.trustedPublicKeyPath,
    });
    expect(receipt.releaseEvidence.status).toBe("validated");
    expect(receipt.humanSignOff.status).toBe("invalid");
    expect(receipt.signed).toBe(false);
    expect(receipt.releaseCandidateEligible).toBe(false);
    expect(receipt.blockers).toContain("Human release sign-off validation failed: Human release sign-off signature verification failed");
  });

  test("fails closed when a referenced gate artifact changes after approval", async () => {
    const application = applicationFixture();
    const approval = signedEvidenceFixture(application);
    writeFileSync(approval.firstEvidenceArtifactPath, "tampered after sign-off\n");
    const receipt = await buildReleaseAttestation({
      repositoryRoot: application.root,
      applicationRoot: application.root,
      artifactRoot: application.artifactRoot,
      createdAt: "2026-07-20T12:00:00Z",
      releaseEvidencePath: approval.evidencePath,
      humanSignOffPath: approval.signOffPath,
      trustedSignOffPublicKeyPath: approval.trustedPublicKeyPath,
    });
    expect(receipt.releaseEvidence.status).toBe("invalid");
    expect(receipt.humanSignOff.status).toBe("invalid");
    expect(receipt.signed).toBe(false);
    expect(receipt.releaseCandidateEligible).toBe(false);
    expect(receipt.blockers.join("\n")).toContain("artifact checksum does not match");
    expect(receipt.blockers.join("\n")).toContain("cannot be verified until the release-gate evidence bundle is valid");
  });

  test("cannot become eligible while the attested interaction manifest still declares a known gap", async () => {
    const application = applicationFixture(["Cross-browser release evidence is incomplete"]);
    const approval = signedEvidenceFixture(application);
    const receipt = await buildReleaseAttestation({
      repositoryRoot: application.root,
      applicationRoot: application.root,
      artifactRoot: application.artifactRoot,
      createdAt: "2026-07-20T12:00:00Z",
      releaseEvidencePath: approval.evidencePath,
      humanSignOffPath: approval.signOffPath,
      trustedSignOffPublicKeyPath: approval.trustedPublicKeyPath,
    });
    expect(receipt.interactionManifest).toMatchObject({ status: "validated", knownGapCount: 1 });
    expect(receipt.releaseEvidence.status).toBe("invalid");
    expect(receipt.signed).toBe(false);
    expect(receipt.releaseCandidateEligible).toBe(false);
    expect(receipt.blockers).toContain("The interaction manifest still declares 1 known release gap(s)");
    expect(receipt.blockers.join("\n")).toContain("knownGapCount does not match the attested interaction manifest");
  });
});
