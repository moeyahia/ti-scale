import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION } from "../HistoricalSourceRootConfiguration";

const SOURCE_COUNT = 156;
const SOURCE_BYTES = 114_061_918;
const MAX_PEAK_RSS_KIB = 1_310_720; // 1.25 GiB; intentionally conservative and ratchetable.
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function exactJsonlBytes(size: number): string {
  const line = `${JSON.stringify({
    timestamp: "2026-07-01T00:00:00.000Z",
    message: `Routine historical status record ${"x".repeat(420)}`,
  })}\n`;
  const lineBytes = Buffer.byteLength(line);
  const repeated = line.repeat(Math.floor(size / lineBytes));
  const remaining = size - Buffer.byteLength(repeated);
  const padded = remaining === 0
    ? repeated
    : `${repeated}${" ".repeat(Math.max(0, remaining - 1))}\n`;
  if (Buffer.byteLength(padded) !== size) throw new Error("Synthetic JSONL byte budget mismatch");
  return padded;
}

function rssKib(pid: number): number {
  try {
    const status = readFileSync(`/proc/${pid}/status`, "utf8");
    return Number(/^VmRSS:\s+(\d+)\s+kB$/mu.exec(status)?.[1] ?? 0);
  } catch {
    return 0;
  }
}

describe("configured historical dry-run memory boundary", () => {
  test("processes the reported 156-file/114,061,918-byte shape without retaining corpus-sized preview pages", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "ti-scale-configured-memory-"));
    temporaryDirectories.push(sandbox);
    const historyRoot = join(sandbox, "history");
    const configurationPath = join(sandbox, "config", "historical-source-roots.json");
    const databasePath = join(sandbox, "canonical.sqlite");
    const output = join(sandbox, "output");
    mkdirSync(join(sandbox, "config"), { recursive: true, mode: 0o700 });

    const ordinarySize = Math.floor(SOURCE_BYTES / SOURCE_COUNT);
    const largerFiles = SOURCE_BYTES % SOURCE_COUNT;
    for (let index = 0; index < SOURCE_COUNT; index += 1) {
      const runtime = join(historyRoot, `source-${String(index).padStart(3, "0")}`, "runtime");
      mkdirSync(runtime, { recursive: true, mode: 0o700 });
      writeFileSync(
        join(runtime, "events.jsonl"),
        exactJsonlBytes(ordinarySize + (index < largerFiles ? 1 : 0)),
        { mode: 0o600 },
      );
    }
    writeFileSync(databasePath, "CANONICAL-DATABASE-MUST-NOT-BE-SCANNED", { mode: 0o600 });
    writeFileSync(configurationPath, `${JSON.stringify({
      schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
      configurationVersion: "bounded-memory-fixture-v1",
      roots: [{ id: "history", path: historyRoot, mode: "history-root", required: true }],
    }, null, 2)}\n`, { mode: 0o600 });
    chmodSync(configurationPath, 0o600);

    const child = Bun.spawn([
      globalThis.process.execPath,
      "run",
      "server/migration/configured-historical-cli.ts",
      "--config", configurationPath,
      "--config-sha256", sha256(configurationPath),
      "--db", databasePath,
      "--output", output,
      "--acknowledge-verified-reference",
      "--acknowledge-attack-knowledge-only",
      "--dry-run",
    ], {
      cwd: globalThis.process.cwd(),
      env: globalThis.process.env,
      stdout: "pipe",
      stderr: "pipe",
    });
    let exited = false;
    const exitPromise = child.exited.finally(() => { exited = true; });
    let peakRssKib = 0;
    while (!exited) {
      peakRssKib = Math.max(peakRssKib, rssKib(child.pid));
      await Bun.sleep(20);
    }
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      exitPromise,
    ]);

    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
    expect(peakRssKib).toBeLessThanOrEqual(MAX_PEAK_RSS_KIB);
    if (globalThis.process.env.TI_SCALE_MEMORY_TEST_REPORT === "1") {
      globalThis.process.stdout.write(`${JSON.stringify({
        sourceCount: SOURCE_COUNT,
        sourceBytes: SOURCE_BYTES,
        peakRssKib,
        ceilingKib: MAX_PEAK_RSS_KIB,
      })}\n`);
    }
    const summary = JSON.parse(stdout) as {
      readonly reportPath: string;
      readonly attackKnowledge: {
        readonly status: string;
        readonly batchesProcessed: number;
        readonly genericSourcesDiscovered: number;
      };
    };
    const report = JSON.parse(readFileSync(summary.reportPath, "utf8")) as {
      readonly inventoryReceipt: { readonly objectCount: number; readonly byteCount: number };
      readonly integrity: { readonly verificationStatus: string };
    };
    expect(summary.attackKnowledge.status).toBe("completed");
    expect(summary.attackKnowledge.batchesProcessed).toBeGreaterThan(1);
    expect(summary.attackKnowledge.genericSourcesDiscovered).toBe(SOURCE_COUNT);
    expect(report.inventoryReceipt).toMatchObject({ objectCount: SOURCE_COUNT, byteCount: SOURCE_BYTES });
    expect(report.integrity.verificationStatus).toBe("deferred");
  }, 120_000);
});
