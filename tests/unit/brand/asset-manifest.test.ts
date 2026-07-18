import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";

interface FileRecord {
  readonly path: string;
  readonly width: number;
  readonly height: number;
  readonly bytes: number;
  readonly sha256?: string;
  readonly alpha?: boolean;
}

interface BrandManifest {
  readonly schemaVersion: string;
  readonly workspace: string;
  readonly provenance: {
    readonly generator: string;
    readonly generators: ReadonlyArray<{
      readonly tool: string;
      readonly assetCount: number;
      readonly generationDates: readonly string[];
    }>;
  };
  readonly assets: ReadonlyArray<{
    readonly id: string;
    readonly kind: string;
    readonly selected?: boolean;
    readonly sourcePrompt: string;
    readonly model: string;
    readonly tool: string;
    readonly source: FileRecord;
    readonly derivedVariants?: readonly FileRecord[];
    readonly generationReceipt?: {
      readonly generationId: string;
      readonly receiptPath: string;
      readonly sourceSha256: string;
    };
  }>;
}

const manifestPath = resolve(import.meta.dirname, "../../../public/brand-v2/manifest.json");
const brandRoot = dirname(manifestPath);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as BrandManifest;

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function expectPackagedFile(record: FileRecord): void {
  const path = resolve(brandRoot, record.path);
  expect(statSync(path).size, record.path).toBe(record.bytes);
  if (record.sha256) expect(sha256(path), record.path).toBe(record.sha256);
}

describe("Ti-Scale production asset provenance", () => {
  test("records the exact generator boundary for every project asset", () => {
    expect(manifest.schemaVersion).toBe("1.0");
    expect(manifest.workspace).toBe("Ti-Scale");
    expect(manifest.provenance.generator).toBe("Higgsfield MCP and repository-native SVG");
    expect(manifest.provenance.generators).toEqual([
      { tool: "Higgsfield MCP", assetCount: 1, generationDates: ["2026-07-18"] },
      { tool: "Repository-native SVG", assetCount: 2, generationDates: ["2026-07-18"] },
    ]);
    expect(manifest.assets).toHaveLength(3);

    for (const asset of manifest.assets) {
      expect(asset.source.path.startsWith("source/")).toBe(true);
      expect(asset.source.width).toBeGreaterThan(0);
      expect(asset.source.height).toBeGreaterThan(0);
      expect(asset.source.bytes).toBeGreaterThan(0);
      expectPackagedFile(asset.source);
      if (asset.kind === "production-identity") {
        expect(asset.tool).toBe("Repository-native SVG");
      } else {
        expect(asset.tool).toContain("Higgsfield MCP");
      }
    }
  });

  test("ships no rejected or green-accented asset in the production manifest", () => {
    expect(manifest.assets.every(({ selected }) => selected !== false)).toBe(true);
    expect(manifest.assets.some(({ kind }) => kind === "research-moodboard")).toBe(false);
    for (const asset of manifest.assets) {
      expect(asset.source.path).not.toContain("rejected");
      expect(asset.sourcePrompt.toLocaleLowerCase("en-US")).not.toContain("acid-lime");
    }
  });

  test("integrity-binds the Higgsfield titanium hero and all responsive variants", () => {
    const hero = manifest.assets.find(({ id }) => id === "ti-scale-higgsfield-titanium-core");
    expect(hero).toBeDefined();
    expect(hero?.kind).toBe("production-hero");
    expect(hero?.selected).toBe(true);
    expect(hero?.model).toBe("recraft_v4_1");
    expect(hero?.tool).toBe("Higgsfield MCP generate_image");
    expect(hero?.generationReceipt).toEqual({
      generationId: "5634dadb-d88e-49f1-a47a-1010008d1543",
      receiptPath: "source/ti-scale-higgsfield-recraft-core-20260718-095533-5634dadb-d88e-49f1-a47a-1010008d1543.json",
      sourceSha256: "4becf93da9ce55dd96d59833870b21ccae128b5e5fd2679443863afc43606107",
    });
    expect(hero?.source).toMatchObject({ width: 1344, height: 768, alpha: false });
    expect(hero?.sourcePrompt).toContain("abstract sculptural titanium scale system");
    expect(hero?.sourcePrompt).toContain("Strictly no green");

    expect(hero?.derivedVariants?.map(({ path, width, height, alpha }) => ({ path, width, height, alpha }))).toEqual([
      { path: "optimized/ti-scale-higgsfield-core-1344.avif", width: 1344, height: 768, alpha: undefined },
      { path: "optimized/ti-scale-higgsfield-core-1344.webp", width: 1344, height: 768, alpha: undefined },
      { path: "optimized/ti-scale-higgsfield-core-1024.avif", width: 1024, height: 585, alpha: undefined },
      { path: "optimized/ti-scale-higgsfield-core-1024.webp", width: 1024, height: 585, alpha: undefined },
      { path: "optimized/ti-scale-higgsfield-core-640.avif", width: 640, height: 366, alpha: undefined },
      { path: "optimized/ti-scale-higgsfield-core-640.webp", width: 640, height: 366, alpha: undefined },
    ]);
    for (const variant of hero?.derivedVariants ?? []) expectPackagedFile(variant);
  });
});
