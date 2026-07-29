import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverLegacySources } from "../SourceDiscovery";

const temporaryDirectories: string[] = [];

afterEach(() => {
  temporaryDirectories.splice(0).forEach((directory) => {
    rmSync(directory, { recursive: true, force: true });
  });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-supplemental-history-"));
  temporaryDirectories.push(directory);
  return directory;
}

function write(path: string, content: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, content, { mode: 0o600 });
}

describe("supplemental historical source discovery", () => {
  test("classifies bounded provider and Markdown history while counting every unsupported boundary", async () => {
    const sandbox = temporaryDirectory();
    const claude = join(sandbox, ".claude", "projects");
    const codex = join(sandbox, ".codex", "sessions");
    const hermes = join(sandbox, "hermes");
    const state = join(sandbox, "state");
    write(
      join(claude, "project", "session.jsonl"),
      `${JSON.stringify({ message: "nginx 1.24.0 failed" })}\n`,
    );
    write(join(codex, "2026", "session.jsonl"), "x".repeat(257));
    write(
      join(hermes, "conversations", "history.md"),
      "# History\n\nApache HTTP Server 2.4.58 path traversal worked.\n",
    );
    write(join(hermes, "unknown.bin"), "unclassified");
    write(join(hermes, "state.db"), "SQLite fixture with a writer");
    write(join(hermes, "state.db-wal"), "active");
    write(join(hermes, "projected-vault", ".obsidian", "config"), "{}");
    write(join(hermes, "projected-vault", "projection.md"), "do not ingest");
    write(
      join(state, "session-logs", "session.system.txt"),
      "OpenSSH 9.2 authentication bypass failed before a bounded retry.\n",
    );

    const roots = [claude, codex, hermes, state];
    const result = await discoverLegacySources(roots, {
      boundedHistoryRoots: roots,
      maximumBoundedSourceBytes: 128,
    });

    expect(result.included.map(({ type }) => type).sort()).toEqual([
      "conversation_markdown",
      "provider_log",
      "provider_session_jsonl",
    ]);
    expect(result.coverage).toMatchObject({
      scannedFiles: 7,
      classifiedFiles: 5,
      includedFiles: 3,
      unsupportedFiles: 1,
      oversizedFiles: 1,
      activeSqliteFiles: 1,
      vaultProjectionDirectories: 1,
    });
    expect(result.excluded.some(({ reason }) => reason.includes("active SQLite"))).toBeTrue();
    expect(result.excluded.some(({ reason }) => reason.includes("8 MiB"))).toBeTrue();
    expect(result.excluded.some(({ reason }) => reason.includes("feedback loop"))).toBeTrue();
    expect(result.included.some(({ absolutePath }) => absolutePath.includes("projected-vault"))).toBeFalse();
  });

  test("fails closed instead of reporting partial supplemental coverage at the file bound", async () => {
    const sandbox = temporaryDirectory();
    const provider = join(sandbox, ".claude", "projects");
    write(join(provider, "one.jsonl"), `${JSON.stringify({ message: "nginx 1.24.0" })}\n`);
    write(join(provider, "two.jsonl"), `${JSON.stringify({ message: "Apache HTTP Server 2.4.58" })}\n`);
    await expect(discoverLegacySources([provider], {
      boundedHistoryRoots: [provider],
      maximumBoundedFiles: 1,
    })).rejects.toThrow("configured bounded file discovery limit");
  });
});
