#!/usr/bin/env bun
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  BRAIN_ATLAS_PINNED_RELEASE,
  generateBrainAtlasConfiguration,
  serializeBrainAtlasConfiguration,
  validateBrainAtlasConfiguration,
} from "../server/vault";

const profileRoot = resolve("deployment/obsidian/brain-atlas");
const dataPath = resolve(profileRoot, "data.json");
const releasePath = resolve(profileRoot, "release.json");
const expectedData = serializeBrainAtlasConfiguration(generateBrainAtlasConfiguration());
const expectedRelease = `${JSON.stringify(BRAIN_ATLAS_PINNED_RELEASE, null, 2)}\n`;
const write = process.argv.slice(2).includes("--write");

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

if (write) {
  writeFileSync(dataPath, expectedData, { encoding: "utf8", mode: 0o600 });
  writeFileSync(releasePath, expectedRelease, { encoding: "utf8", mode: 0o600 });
}

const actualData = readFileSync(dataPath, "utf8");
const actualRelease = readFileSync(releasePath, "utf8");
validateBrainAtlasConfiguration(JSON.parse(actualData));
if (
  canonical(JSON.parse(actualData)) !== canonical(JSON.parse(expectedData))
  || canonical(JSON.parse(actualRelease)) !== canonical(JSON.parse(expectedRelease))
) {
  throw new Error("Brain Atlas deployment profile differs from the generated registry and pinned release");
}
process.stdout.write(`${JSON.stringify({
  status: "verified",
  profile: "deployment/obsidian/brain-atlas",
  release: BRAIN_ATLAS_PINNED_RELEASE.version,
}, null, 2)}\n`);
