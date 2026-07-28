import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseAutonomousDnsRuntimeConfiguration,
} from "../../../server/app/AutonomousDnsActivationCoordinator";
import {
  parsePinnedLocalCveCandidateCatalogDocument,
} from "../../../server/cve-intelligence";
import {
  argumentsByName,
} from "../../generate-full-tcp-safe-recon-activation";
import {
  AUTONOMOUS_CVE_CANDIDATE_CATALOG_NAME,
  FULL_TCP_ACTIVATION_RUNTIME_NAME,
  type FullTcpSafeReconActivationResult,
} from "../FullTcpSafeReconActivationDocuments";

const REPOSITORY_ROOT = join(import.meta.dir, "../../..");
const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function sha256(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function fixture(): Readonly<{
  root: string;
  manifest: string;
  runtime: string;
  catalog: string;
  output: string;
}> {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-full-tcp-cli-"));
  temporaryRoots.push(root);
  chmodSync(root, 0o700);
  const manifest = join(root, "manifest.json");
  const runtime = join(root, "runtime.json");
  const catalog = join(root, "catalog.json");
  copyFileSync(
    join(
      REPOSITORY_ROOT,
      "deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
    ),
    manifest,
  );
  copyFileSync(
    join(
      REPOSITORY_ROOT,
      "deployment/runtime-config/autonomous-dns-local-runtime.v1.json",
    ),
    runtime,
  );
  writeFileSync(catalog, `${JSON.stringify({
    schemaVersion: "ti-scale.authoritative-cve-candidate-catalog.v1",
    catalogId: "catalog:activation-cli-fixture",
    catalogVersion: "activation-cli-fixture-v1",
    generatedAt: "2026-07-22T11:00:00.000Z",
    candidates: [{
      cveId: "CVE-2026-12345",
      title: "Fixture Server bounded parser issue",
      component: { product: "Fixture Server" },
      affectedRanges: [{
        id: "affected-fixture-1",
        scheme: "semver",
        lower: { version: "1.0.0", inclusive: true },
        upper: { version: "2.0.0", inclusive: false },
      }],
      sources: [{
        kind: "nvd",
        authority: "NIST National Vulnerability Database",
        recordUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        retrievedAt: "2026-07-22T11:00:00.000Z",
        sourceVersion: "NVD API 2.0 fixture snapshot",
        contentSha256: "a".repeat(64),
        retrievalReceiptId: "receipt:activation-cli-cve",
        retrievalReceiptSha256: "b".repeat(64),
      }],
    }],
  }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  chmodSync(manifest, 0o600);
  chmodSync(runtime, 0o600);
  return Object.freeze({
    root,
    manifest,
    runtime,
    catalog,
    output: join(root, "generated"),
  });
}

describe("generate-full-tcp-safe-recon-activation CLI", () => {
  test("requires the complete catalogue pin and validates the optional cap", () => {
    const required = [
      "--manifest", "/tmp/manifest.json",
      "--manifest-sha256", "a".repeat(64),
      "--runtime", "/tmp/runtime.json",
      "--runtime-sha256", "b".repeat(64),
      "--output", "/tmp/generated",
    ];
    expect(() => argumentsByName([
      ...required,
      "--cve-candidate-catalog", "/tmp/catalog.json",
    ])).toThrow("requires both");
    expect(() => argumentsByName([
      ...required,
      "--maximum-cve-candidates-per-product", "10",
    ])).toThrow("require the complete pinned catalogue");
    expect(() => argumentsByName([
      ...required,
      "--cve-candidate-catalog", "/tmp/catalog.json",
      "--cve-candidate-catalog-sha256", "c".repeat(64),
      "--maximum-cve-candidates-per-product", "101",
    ])).toThrow("1 through 100");
  });

  test("passes the pinned catalogue through the executable CLI into one deployable bundle", async () => {
    const setup = fixture();
    const manifestSha256 = sha256(readFileSync(setup.manifest));
    const runtimeSha256 = sha256(readFileSync(setup.runtime));
    const catalogSha256 = sha256(readFileSync(setup.catalog));
    const child = Bun.spawn([
      globalThis.process.execPath,
      join(REPOSITORY_ROOT, "scripts/generate-full-tcp-safe-recon-activation.ts"),
      "--manifest", setup.manifest,
      "--manifest-sha256", manifestSha256,
      "--runtime", setup.runtime,
      "--runtime-sha256", runtimeSha256,
      "--cve-candidate-catalog", setup.catalog,
      "--cve-candidate-catalog-sha256", catalogSha256,
      "--maximum-cve-candidates-per-product", "7",
      "--output", setup.output,
    ], {
      cwd: REPOSITORY_ROOT,
      stdout: "pipe",
      stderr: "pipe",
      env: { ...globalThis.process.env },
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(stderr).toBe("");
    expect(exitCode).toBe(0);
    const result = JSON.parse(stdout) as FullTcpSafeReconActivationResult;
    expect(result.generated.cveCandidateCatalog?.sha256).toBe(catalogSha256);
    expect(existsSync(join(setup.output, AUTONOMOUS_CVE_CANDIDATE_CATALOG_NAME)))
      .toBeTrue();
    const runtime = parseAutonomousDnsRuntimeConfiguration(JSON.parse(readFileSync(
      join(setup.output, FULL_TCP_ACTIVATION_RUNTIME_NAME),
      "utf8",
    )) as unknown);
    expect(runtime.cveApplicability).toMatchObject({
      catalogId: "catalog:activation-cli-fixture",
      maximumCandidatesPerProduct: 7,
      nvdEnrichment: "disabled",
    });
    if (!runtime.cveApplicability) throw new Error("CLI did not enable CVE applicability");
    expect(parsePinnedLocalCveCandidateCatalogDocument(JSON.parse(readFileSync(
      result.generated.cveCandidateCatalog!.path,
      "utf8",
    )) as unknown).catalogId).toBe(runtime.cveApplicability.catalogId);
  });
});
