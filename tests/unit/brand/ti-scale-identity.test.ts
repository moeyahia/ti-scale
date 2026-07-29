import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";

const applicationRoot = resolve(import.meta.dirname, "../../..");
const markPath = resolve(applicationRoot, "public/brand-v2/source/ti-scale-mark.svg");
const wordmarkPath = resolve(applicationRoot, "public/brand-v2/source/ti-scale-wordmark.svg");
const mark = readFileSync(markPath, "utf8");
const wordmark = readFileSync(wordmarkPath, "utf8");

function source(path: string): string {
  return readFileSync(resolve(applicationRoot, path), "utf8");
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function expectSafeAccessibleSvg(svg: string, viewBox: string): void {
  expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
  expect(svg).toContain(`viewBox="${viewBox}"`);
  expect(svg).toContain('role="img"');
  expect(svg).toMatch(/aria-labelledby="[^"]+-title [^"]+-description"/u);
  expect(svg).toMatch(/<title id="[^"]+-title">[^<]+<\/title>/u);
  expect(svg).toMatch(/<desc id="[^"]+-description">[^<]+<\/desc>/u);
  for (const forbidden of ["<script", "<foreignObject", "<image", "<text", "<style", "href=", "url("]) {
    expect(svg).not.toContain(forbidden);
  }
  expect(svg).not.toMatch(/\son[a-z]+=/u);
  expect(svg.match(/#[0-9A-Fa-f]{6}/gu) ?? []).toEqual(expect.arrayContaining(["#C8C4BD", "#6C737A", "#111315", "#0A0A0B"]));
  expect(new Set(svg.match(/#[0-9A-Fa-f]{6}/gu) ?? [])).toEqual(new Set(["#C8C4BD", "#6C737A", "#111315", "#0A0A0B"]));
}

describe("standalone Ti-Scale native identity", () => {
  test("ships compact, accessible, path-only SVG geometry with stable integrity", () => {
    expectSafeAccessibleSvg(mark, "0 0 64 64");
    expectSafeAccessibleSvg(wordmark, "0 0 420 80");
    expect(mark).toContain("abstract titanium T spine interlocked with a segmented S-shaped armor scale");
    expect(wordmark).toContain(">Ti-Scale</title>");
    expect(statSync(markPath).size).toBe(656);
    expect(statSync(wordmarkPath).size).toBe(1250);
    expect(sha256(markPath)).toBe("2fac133ce565d70d5dc14791934c3dcd76c77ae7d283ca435ad40f8fbd8b6731");
    expect(sha256(wordmarkPath)).toBe("509eed9f2539fd3f8dba48543dc2b9b0d6bbf9321ba749644dcde213ebf23646");
  });

  test("uses the wordmark in the shell and the mark for authentication and favicon", () => {
    expect(source("src/app/shell/AppShell.tsx")).toContain('assetUrl("brand-v2/source/ti-scale-wordmark.svg")');
    expect(source("src/app/providers/AuthProvider.tsx")).toContain('assetUrl("brand-v2/source/ti-scale-mark.svg")');
    expect(source("index.html")).toContain('href="/brand-v2/source/ti-scale-mark.svg"');
  });

  test("has no V2 legacy-logo copy, sync hook, build dependency, or release claim", () => {
    const retiredLogoFilename = ["Logo", "svg"].join(".");
    const retiredSyncName = ["sync", "logo"].join("-");
    const retiredScriptKeys = [["logo", "sync"].join(":"), ["logo", "verify"].join(":")];
    expect(existsSync(resolve(applicationRoot, "public", retiredLogoFilename))).toBe(false);
    expect(existsSync(resolve(applicationRoot, "scripts", `${retiredSyncName}.ts`))).toBe(false);

    const standaloneBoundary = [
      source("src/app/shell/AppShell.tsx"),
      source("src/app/providers/AuthProvider.tsx"),
      source("index.html"),
      source("package.json"),
      source("playwright.config.ts"),
      source("scripts/release-attestation.ts"),
      source("public/brand-v2/manifest.json"),
    ].join("\n");
    expect(standaloneBoundary).not.toContain(retiredLogoFilename);
    expect(standaloneBoundary).not.toContain(retiredSyncName);
    for (const retiredScriptKey of retiredScriptKeys) expect(standaloneBoundary).not.toContain(retiredScriptKey);
    expect(standaloneBoundary).not.toContain(["webapp", "public"].join("/"));
    expect(source("scripts/release-attestation.ts")).toContain("identityMark");
    expect(source("scripts/release-attestation.ts")).toContain("identityWordmark");
  });
});
