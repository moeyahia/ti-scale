import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hashJson } from "../../orchestration/serialization";
import {
  LEGACY_HISTORICAL_CANDIDATE_FILE,
  LEGACY_HISTORICAL_RECEIPT_FILE,
  type LegacyHistoricalCollectionReceipt,
} from "../legacy-historical-cli";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-cli-"));
  temporaryDirectories.push(directory);
  return directory;
}

function write(path: string, content: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, content, { encoding: "utf8", mode: 0o600 });
}

async function runCli(args: readonly string[]): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const child = Bun.spawn([
    globalThis.process.execPath,
    "run",
    "server/migration/legacy-historical-cli.ts",
    ...args,
  ], {
    cwd: globalThis.process.cwd(),
    env: globalThis.process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stdout, stderr };
}

interface CandidateDocument {
  readonly schemaVersion: string;
  readonly classification: {
    readonly sensitivity: string;
    readonly disclosure: string;
    readonly lifecycle: string;
    readonly reusableMemoryEligible: boolean;
    readonly directReusableMemoryWriteAllowed: boolean;
    readonly intendedNextStep: string;
  };
  readonly discovery: {
    readonly sources: readonly { readonly canonicalPath: string }[];
    readonly excluded: readonly { readonly category: string }[];
  };
  readonly parseResults: readonly {
    readonly candidates: readonly {
      readonly disclosure: string;
      readonly lifecycle: string;
      readonly reusableMemoryEligible: boolean;
      readonly privatePayload: unknown;
    }[];
  }[];
  readonly integrity: {
    readonly algorithm: string;
    readonly payloadHash: string;
    readonly receiptHash: string;
  };
}

describe("missed historical source collection CLI", () => {
  test("writes deterministic content-free receipt and mode-0600 private candidates without touching the active DB", async () => {
    const sandbox = temporaryDirectory();
    const root = join(sandbox, "history");
    const activeDatabase = join(root, "active", "ti-scale.sqlite");
    const outputOne = join(sandbox, "collection-one");
    const outputTwo = join(sandbox, "collection-two");
    const operatorToken = "operator-token-that-must-never-be-printed";
    write(activeDatabase, "ACTIVE-DATABASE-SENTINEL");
    write(join(root, ".claude", "projects", "project-a", "session.jsonl"), JSON.stringify({
      type: "assistant",
      message: "Use a bounded worker health check before retry",
      token: operatorToken,
      timestamp: "2026-07-20T10:00:00.000Z",
    }));
    write(
      join(root, "sessions", "old.system.txt"),
      "Worker stalled before a trustworthy terminal result\nRecycle the worker and verify health\n",
    );
    const activeBefore = readFileSync(activeDatabase);
    const activeModifiedBefore = statSync(activeDatabase).mtimeMs;
    const common = [
      "collect",
      "--root", root,
      "--active-db", activeDatabase,
      "--acknowledge-local-only",
    ];

    const first = await runCli([...common, "--output", outputOne]);
    expect(first.exitCode).toBe(0);
    expect(first.stderr).toBe("");
    const receiptPathOne = join(outputOne, LEGACY_HISTORICAL_RECEIPT_FILE);
    const candidatePathOne = join(outputOne, LEGACY_HISTORICAL_CANDIDATE_FILE);
    const receiptTextOne = readFileSync(receiptPathOne, "utf8");
    const candidateTextOne = readFileSync(candidatePathOne, "utf8");
    const receiptOne = JSON.parse(receiptTextOne) as LegacyHistoricalCollectionReceipt;
    const candidateOne = JSON.parse(candidateTextOne) as CandidateDocument;

    expect(JSON.parse(first.stdout)).toEqual(receiptOne);
    expect(receiptOne.schemaVersion).toBe("ti_scale.legacy_historical_collection_receipt/v1");
    expect(receiptOne.safety).toEqual(expect.objectContaining({
      disclosure: "local_only",
      activeDatabaseOpened: false,
      activeDatabaseWrites: false,
      directReusableMemoryWrites: false,
      outputFileMode: "0600",
    }));
    expect(receiptOne.counts.sources).toBe(2);
    expect(receiptOne.counts.candidates).toBe(3);
    expect(receiptOne.counts.exclusions).toBeGreaterThanOrEqual(1);
    const { receiptHash, ...receiptBody } = receiptOne;
    expect(receiptHash).toBe(hashJson(receiptBody));

    expect(candidateOne.schemaVersion).toBe("ti_scale.legacy_historical_candidates/v1");
    expect(candidateOne.classification).toEqual({
      sensitivity: "private",
      disclosure: "local_only",
      lifecycle: "candidate",
      reusableMemoryEligible: false,
      directReusableMemoryWriteAllowed: false,
      intendedNextStep: "semantic_extraction_review",
    });
    expect(candidateOne.discovery.sources.some(({ canonicalPath }) => canonicalPath === activeDatabase)).toBe(false);
    expect(candidateOne.discovery.excluded.some(({ category }) => category === "canonical_database")).toBe(true);
    expect(candidateOne.parseResults.flatMap(({ candidates }) => candidates).every((candidate) =>
      candidate.disclosure === "local_only"
      && candidate.lifecycle === "candidate"
      && candidate.reusableMemoryEligible === false)).toBe(true);
    const { integrity, ...candidatePayload } = candidateOne;
    expect(integrity).toEqual({
      algorithm: "sha256",
      payloadHash: hashJson(candidatePayload),
      receiptHash,
    });
    expect(candidateTextOne).not.toContain(operatorToken);
    expect(candidateTextOne).toContain("[REDACTED]");
    expect(receiptTextOne).not.toContain(operatorToken);
    expect(receiptTextOne).not.toContain(root);
    expect(receiptTextOne).not.toContain("bounded worker health check");
    expect(statSync(receiptPathOne).mode & 0o777).toBe(0o600);
    expect(statSync(candidatePathOne).mode & 0o777).toBe(0o600);
    expect(readFileSync(activeDatabase)).toEqual(activeBefore);
    expect(statSync(activeDatabase).mtimeMs).toBe(activeModifiedBefore);

    const second = await runCli([...common, "--output", outputTwo]);
    expect(second.exitCode).toBe(0);
    expect(second.stderr).toBe("");
    expect(readFileSync(join(outputTwo, LEGACY_HISTORICAL_RECEIPT_FILE), "utf8")).toBe(receiptTextOne);
    expect(readFileSync(join(outputTwo, LEGACY_HISTORICAL_CANDIDATE_FILE), "utf8")).toBe(candidateTextOne);
    expect(second.stdout).toBe(first.stdout);
  });

  test("fails closed for a missing active-DB exclusion, an in-root output, or any nonempty output", async () => {
    const sandbox = temporaryDirectory();
    const root = join(sandbox, "history");
    const activeDatabase = join(root, "active.sqlite");
    const sourceToken = "source-token-that-must-not-reach-stderr";
    write(activeDatabase, "ACTIVE-DATABASE-SENTINEL");
    write(join(root, "sessions", "old.system.txt"), `token: ${sourceToken}\n`);

    const noExclusionOutput = join(sandbox, "no-exclusion");
    const noExclusion = await runCli([
      "collect", "--root", root, "--output", noExclusionOutput, "--acknowledge-local-only",
    ]);
    expect(noExclusion.exitCode).toBe(1);
    expect(noExclusion.stderr).toContain("At least one --active-db is required");
    expect(existsSync(noExclusionOutput)).toBe(false);

    const inRootOutput = join(root, "generated-candidates");
    const inRoot = await runCli([
      "collect", "--root", root, "--active-db", activeDatabase,
      "--output", inRootOutput, "--acknowledge-local-only",
    ]);
    expect(inRoot.exitCode).toBe(1);
    expect(inRoot.stderr).toContain("outside every historical source root");
    expect(existsSync(inRootOutput)).toBe(false);

    const nonemptyOutput = join(sandbox, "already-used");
    write(join(nonemptyOutput, "keep.txt"), "do-not-overwrite");
    const nonempty = await runCli([
      "collect", "--root", root, "--active-db", activeDatabase,
      "--output", nonemptyOutput, "--acknowledge-local-only",
    ]);
    expect(nonempty.exitCode).toBe(1);
    expect(nonempty.stderr).toContain("overwrite and resume are intentionally unsupported");
    expect(readFileSync(join(nonemptyOutput, "keep.txt"), "utf8")).toBe("do-not-overwrite");
    expect(existsSync(join(nonemptyOutput, LEGACY_HISTORICAL_RECEIPT_FILE))).toBe(false);
    expect(existsSync(join(nonemptyOutput, LEGACY_HISTORICAL_CANDIDATE_FILE))).toBe(false);
    const loosenedBoundsOutput = join(sandbox, "loosened-bounds");
    const loosenedBounds = await runCli([
      "collect", "--root", root, "--active-db", activeDatabase,
      "--output", loosenedBoundsOutput, "--max-text-bytes", `${8 * 1024 * 1024 + 1}`,
      "--acknowledge-local-only",
    ]);
    expect(loosenedBounds.exitCode).toBe(1);
    expect(loosenedBounds.stderr).toContain("--max-text-bytes is outside its safe range");
    expect(existsSync(loosenedBoundsOutput)).toBe(false);
    expect(`${noExclusion.stdout}${noExclusion.stderr}${inRoot.stdout}${inRoot.stderr}${nonempty.stdout}${nonempty.stderr}${loosenedBounds.stdout}${loosenedBounds.stderr}`)
      .not.toContain(sourceToken);
  });
});
