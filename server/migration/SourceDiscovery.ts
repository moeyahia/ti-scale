import { createHash } from "node:crypto";
import {
  createReadStream,
  lstatSync,
  openSync,
  closeSync,
  readSync,
  readdirSync,
  realpathSync,
  statSync,
} from "node:fs";
import { basename, relative, resolve, sep } from "node:path";
import type { LegacySource, LegacySourceType, SourceInventory } from "./types";

const DENIED_BASENAME = /(?:^|[._-])(?:auth|credential|credentials|secret|secrets|token|tokens|key|keys|shell[-_]?snapshot|\.env)(?:$|[._-])/iu;
const DENIED_KEY_FILE = /^(?:id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx|keystore|jks)|request_dump_.*)$/iu;
const DENIED_PATH = /(?:^|\/)(?:node_modules|\.git|dist|build|cache|tmp|backups?)(?:\/|$)/iu;
const BACKUP_SUFFIX = /(?:\.bak(?:\.|$)|\.backup(?:\.|$)|\.old$|\.pre-[^/]+$)/iu;

function classify(relativePath: string): LegacySourceType | undefined {
  const normalized = relativePath.split(sep).join("/");
  const name = basename(normalized).toLowerCase();
  if (name === "kanban.db") return "kanban_sqlite";
  if (name === "state.db") return "conversation_state_sqlite";
  if (/\/runtime\/runs\/[^/]+\.json$/iu.test(`/${normalized}`)) return "run_json";
  if (/\/runtime\/memory\/items\.json$/iu.test(`/${normalized}`)) return "memory_json";
  if (/\/runtime\/training\/lessons\.json$/iu.test(`/${normalized}`)) return "training_json";
  if (/\/runtime\/(?:events|raw[^/]*)\.jsonl$/iu.test(`/${normalized}`)) return "event_jsonl";
  if (/\/(?:llm-logs|session-logs)\/[^/]+\.jsonl$/iu.test(`/${normalized}`)) return "raw_llm_jsonl";
  if (/\/sessions\/[^/]+\.jsonl$/iu.test(`/${normalized}`)) return "raw_llm_jsonl";
  if (/\/sessions\/[^/]+\.json$/iu.test(`/${normalized}`) && !/^request_dump_/iu.test(name)) return "session_json";
  if (/\/(?:logs|application\/logs)\/[^/]+\.(?:log|txt)$/iu.test(`/${normalized}`)) return "dashboard_log";
  if (/\/artifacts?\//iu.test(`/${normalized}`)) return "artifact";
  return undefined;
}

async function hashFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

function beginsWithPrivateKey(path: string): boolean {
  const descriptor = openSync(path, "r");
  try {
    const buffer = Buffer.allocUnsafe(65_536);
    const length = readSync(descriptor, buffer, 0, buffer.length, 0);
    return /-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(buffer.subarray(0, length).toString("utf8"));
  } finally { closeSync(descriptor); }
}

function safelyInside(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value === "" || (!value.startsWith(`..${sep}`) && value !== "..");
}

/** Allowlist-based discovery; secret/config files are never selected even when explicitly rooted. */
export async function discoverLegacySources(sourceRoots: readonly string[]): Promise<SourceInventory> {
  const included: LegacySource[] = [];
  const excluded: Array<{ absolutePath: string; reason: string }> = [];
  const seen = new Set<string>();

  for (const requestedRoot of sourceRoots) {
    const absoluteRoot = resolve(requestedRoot);
    let rootReal: string;
    try {
      rootReal = realpathSync(absoluteRoot);
    } catch {
      excluded.push({ absolutePath: absoluteRoot, reason: "source root does not exist" });
      continue;
    }
    const rootStat = lstatSync(rootReal);
    const files: string[] = [];
    if (rootStat.isFile()) files.push(rootReal);
    else if (rootStat.isDirectory()) {
      const pending = [rootReal];
      while (pending.length) {
        const directory = pending.pop()!;
        for (const entry of readdirSync(directory, { withFileTypes: true })) {
          const candidate = resolve(directory, entry.name);
          if (entry.isSymbolicLink()) {
            excluded.push({ absolutePath: candidate, reason: "symbolic links are not migrated" });
            continue;
          }
          if (entry.isDirectory()) {
            const rel = relative(rootReal, candidate).split(sep).join("/");
            if (!DENIED_PATH.test(`/${rel}/`)) pending.push(candidate);
            continue;
          }
          if (entry.isFile()) files.push(candidate);
        }
      }
    }

    for (const path of files.sort()) {
      let real: string;
      try { real = realpathSync(path); }
      catch {
        excluded.push({ absolutePath: path, reason: "source disappeared during discovery" });
        continue;
      }
      if (!safelyInside(rootReal, real) || seen.has(real)) continue;
      seen.add(real);
      const rel = rootStat.isFile() ? basename(real) : relative(rootReal, real);
      const normalized = rel.split(sep).join("/");
      if (DENIED_BASENAME.test(basename(real)) || DENIED_KEY_FILE.test(basename(real)) || DENIED_PATH.test(`/${normalized}`) || BACKUP_SUFFIX.test(basename(real))) {
        excluded.push({ absolutePath: real, reason: "sensitive, generated, or backup filename denied" });
        continue;
      }
      const type = classify(normalized);
      if (!type) continue;
      if (type === "artifact" && beginsWithPrivateKey(real)) {
        excluded.push({ absolutePath: real, reason: "private-key material is never migrated as an artifact" });
        continue;
      }
      let fileStat;
      try { fileStat = statSync(real); }
      catch {
        excluded.push({ absolutePath: real, reason: "source changed during discovery" });
        continue;
      }
      included.push({
        absolutePath: real,
        relativePath: normalized,
        root: rootReal,
        type,
        sha256: await hashFile(real),
        byteSize: fileStat.size,
        modifiedAt: fileStat.mtime.toISOString(),
      });
    }
  }

  return { included, excluded };
}
